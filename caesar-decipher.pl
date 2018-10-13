#!/usr/bin/env perl
#
## firexfly@users.noreply.github.com
## caesar-decipher
#
# New BSD License (http://www.opensource.org/licenses/BSD-3-Clause)
# Copyright (c) 2018, firexfly
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
#	1. Redistributions of source code must retain the above copyright notice, this 
#	    list of conditions and the following disclaimer.
#
#	2. Redistributions in binary form must reproduce the above copyright notice, 
#	    this list of conditions and the following disclaimer in the documentation 
#	    and/or other materials provided with the distribution.
#
#	3. Neither the name of the copyright holder nor the names of its contributors 
#	    may be used to endorse or promote products derived from this software 
#	    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS 
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY 
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

use strict;
use warnings;
use 5.014;
use autodie;
use File::Spec;

### CUSTOM SETTINGS ###


# Path to custom dictionary
my $path_to_dictionary;

# No. of plaintext candidates to display, default is best match only
# Set to 0 to display all candidate plaintexts as it wouldn't make sense to display none
my $candidate_pt_to_display = 1;


### END CUSTOM SETTINGS ###

### subs ###

sub get_ciphertext {
    my @input;
    while (<>) {
        push @input, $_;
    }
    if (not @input) { #No input
		say "No input, retry.";
		return get_ciphertext();
	}
    @input;
}

sub get_dict { # store dictionary in a hash
    my %dict;
    # use defined or to attempt to open the UNIX words file if no custom dictionary is set
    # catch error opening dictionary and continue without advising the user to set candidate_pt_to_display to 0 to see plaintexts
    eval { open DICTFETCH, '<', $path_to_dictionary // File::Spec->catfile(File::Spec->rootdir(), 'usr', 'share', 'dict', 'words') };
    warn "Continuing without dictionary, set candidate_pt_to_display to 0 to display all plaintexts\nError: $@" and return %dict if $@;
    while (<DICTFETCH>) {
        chomp;
        $dict{$_} = 1;
    }	
    close DICTFETCH;
    %dict;
}

sub match_ciphertext {
    my ($dictionary, $candidate_pt, $index) = @_;
    my ($total_words, $matches) = (0, 0);
    # return from recursion once we have gone through all plaintext candidates
    return if $index >= scalar @$candidate_pt;
    # get plaintext candidates and break them up into separate words
    # use a filehandle to manipulate the candidate plaintexts one line at a time
    open my $candidate_pt_fh, '<', \ $candidate_pt->[$index][0];
    while (<$candidate_pt_fh>) {
        my @match_words = split (/\s/, $_);
        $total_words += scalar @match_words;
        # loop through array of plaintext candidate words and try to match against dictionary
        for (@match_words) {
            # Remove punctuation from end for match. (nondestructive substitution)
            (my $test_match = $_) =~ s/[^a-z]+\z//aii;
            $matches += 1 if (exists $dictionary->{lc $test_match}); # match lowercase version
        }
    }
    # push number of words & matches onto the array of plaintext candidates
    # push index on the end as well so we can show the shift value of the cipher
    # should probably just rewrite this with a hash to make easier to understand
    push (@{ $candidate_pt->[$index] }, ($total_words, $matches, $index + 1));
    # recursion - note: dictionary and candidate_pt arguments are references
    &match_ciphertext ($dictionary, $candidate_pt, $index + 1);
}

sub calculate_shift {
    my $offset = shift;

    if ($offset == 13) {
        return "ROT13";
    } elsif ($offset == 26) {
        return "Original";
    } else {
        my $left_shift = 26 - $offset;
        return "Caesar cipher left shift: $left_shift";
    }
}

### Main ###

# If a file was given as input, check it exists and is not empty.
if (@ARGV == 0) {
    print "Please enter ciphertext below:\n";
} else {
    for (@ARGV) {
        if (! -e $_) { #File does not exist
            die "Error: No such file as '$_'\n";
        } elsif (-z _) { #File has zero size (special _ filehandle to avoid extra stat)
            die "Error: File '$_' is empty\n";
        }
    }
}
# Get ciphertext
my @ciphertext = &get_ciphertext;
# Separate the ciphertext into an array of individual letters
my @chars = map { split (//, $_) } @ciphertext;
my @candidate_pt; # array for plaintext candidates

# Create plaintext candidates
# this should probably be changed so ciphertext is at index 0
for my $counter (0..25) {
    for (@chars) {
        if (/[a-y]/aii) { # increment letters a to y
            push(@{ $candidate_pt[$counter] }, ++$_);
        } elsif (/z/aii) { # reset to a when we reach z
            my $z_char = $_ =~ /z/ ? "a" : "A";
            push(@{ $candidate_pt[$counter] }, $z_char);
        } else { # spaces and punctuation pushed onto array unchanged
            push(@{ $candidate_pt[$counter] }, $_);
        }
    }
    @chars = @{ $candidate_pt[$counter] };
}

# Fetch the system dictionary to check for english plaintext
my %dictionary = &get_dict;

for my $counter (0..25) {
    # join the characters to make an array of possible plaintexts
    @{ $candidate_pt[$counter] } = join ('', @{ $candidate_pt[$counter] });
}

# split on spaces & check against dictionary then present matches as per user preference
&match_ciphertext (\%dictionary, \@candidate_pt, 0);

# print candidate plaintexts with number of words matched against dictionary
for my $candidate (sort {
    $b->[2] <=> $a->[2]
} @candidate_pt) {
    state $candidate_count ++; # display set number of results
    if ($candidate->[2] || $candidate_pt_to_display == 0) { # if at least 1 word matched dictionary
        my ($total_words, $guess) = @$candidate[1,2];
        # get shift value - run sub to get non right shift
        my $shift_value = $candidate->[-1] < 13 ? "Caesar cipher right shift: $candidate->[-1]" : &calculate_shift ($candidate->[-1]);
        say "Candidate plaintext - $shift_value (matches $guess\/", $total_words, " words):";
        print $candidate->[0];
        say "---------------------------------------";
    }
    last if $candidate_count >= $candidate_pt_to_display && $candidate_pt_to_display > 0;
}

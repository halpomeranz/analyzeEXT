#!/usr/bin/perl
#
# AnalyzeEXT - parse data blocks for EXT directory data
#
# Detailed documentation on EXT4 can be found here:
# https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
# https://digital-forensics.sans.org/blog/tags/ext4
#
# Hal Pomeranz (hal@deer-run.com), 2017-06-12
#
# No warranty expressed or implied.
# Distributed under the Creative Commons "Attribution" (CC BY) License
# See https://creativecommons.org/licenses/

use strict;
use vars qw($opt_b $opt_D $opt_H $opt_P);
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION = 1;       # Terminate after --help

sub HELP_MESSAGE { 
    die <<"EoUseMsg";
Usage: cat image | $0 [-DP] [-H] [-b blocksize]

-D        Output details of all directory entries found
-P        Output full directory paths (best guess)
-H        Output header labels

-b size   Specify an alternate block size (default 4096)
EoUseMsg
}

getopts('b:DHP') || HELP_MESSAGE();
my $Block_Size = $opt_b || 4096;
my $Show_Details = $opt_D;
my $Show_Paths = $opt_P;
my $Show_Headers = $opt_H;

$Show_Paths = 1 unless ($Show_Details);      # Default is compute path info



my %File_Type_Char = ( '1' => 'f', '2' => 'd', '3' => 'c', '4' => 'b', 
		       '5' => 'p', '6' => 's', '7' => 'l' );

my $buffer;
my $blocknum = -1;
my($ref, $inode, %Parent_Inode, %File_Name);


print join("\t", 'Block', 'Offset', 'Filename', 'Inode', 
	         'Type', 'Size of Entry', 'Filename Len', 
                 'Allocated', 'Notes'), "\n" 
    if ($Show_Details && $Show_Headers);

while (sysread(STDIN, $buffer, $Block_Size)) {
    $blocknum += 1;
    my $file_list = parse_dir_block($buffer);    # returns null list if not parsable
    next unless (@{$file_list});

    my $dir_start = ($$file_list[0]{'filename'} eq '.' && $$file_list[1]{'filename'} eq '..');
    my $htree_blocks = 0;
    my($this_inode, $parent) = ();

    if ($dir_start) {
	my $dot_ref = shift(@{$file_list});
	$this_inode = $$dot_ref{'inode'};
	my $dotdot_ref = shift(@{$file_list});
	$parent =  $$dotdot_ref{'inode'};
	$Parent_Inode{$this_inode}{$parent} += 1;

	$htree_blocks = parse_htree_root($buffer);

	if ($Show_Details) {
	    my $extra = $htree_blocks ? "$htree_blocks htree leaf blocks" : 'directory is one block';
	    output_entry_info($dot_ref, $blocknum, $this_inode, $parent, $extra);
	    output_entry_info($dotdot_ref, $blocknum, $this_inode, $parent);
	}
    }

    foreach $ref (@${file_list}) {
	output_entry_info($ref, $blocknum, $this_inode, $parent) if ($Show_Details);
	next unless ($Show_Paths);

	# %File_Name tracks a heuristic score for how likely a given file name is
        # to be associated with a particular inode. This score is used to create
        # paths back to the root in make_best_path().
	#
	# Three criteria determine the value of a particular directory entry:
        # 1. Is in in an initial directory block (with the "." and ".." links)?
        # 2. Did we carve it from the slack after an htree dx_root record?
	# 3. Is is a deleted (carved) record or not?
	# The score values are based on limited testing, and may need tweaking.
	#
	my $key = "$$ref{'filename'}/$$ref{'type'}/$this_inode";
	$File_Name{$$ref{'inode'}}{$key} += ($dir_start) ? 2 : 1;
	$File_Name{$$ref{'inode'}}{$key} += 2 if ($htree_blocks);
	$File_Name{$$ref{'inode'}}{$key} += 3 if (!$htree_blocks && !$$ref{'carved'});
    }
}


exit(0) unless ($Show_Paths);
print "\n\n" if ($Show_Details && $Show_Headers);
print "Inode\tPath Info\n" if ($Show_Headers);


# %Max_Dir_Score is used as a secondary sort criteria in make_best_path().
# It's the highest heuristic score for a directory type entry for a given inode.
my %Max_Dir_Score = ();
foreach $inode (keys(%File_Name)) {
    my $best_dir = (sort { $File_Name{$inode}{$b} <=> $File_Name{$inode}{$a} } 
		    grep(m|/2/|, keys(%{$File_Name{$inode}})))[0];
    $Max_Dir_Score{$inode} = $File_Name{$inode}{$best_dir};
}

my %Paths = ( 2 => '' );
foreach $inode (sort {$a <=> $b} keys(%Parent_Inode)) {
    $Paths{$inode} = make_best_path($inode) unless (defined($Paths{$inode}));
    print "$inode\t$Paths{$inode}\n";
}

###########################################################################################
###
### Program ends. Subroutines below.
###
###########################################################################################


sub make_best_path {
    my($inode) = @_;
    my($parent, $dirname, $type, $key);

    # If we didn't find a directory entry for this inode, give up
    return('???') if (!defined($File_Name{$inode}));

    # If we didn't find a "." link associated with this inode, 
    # not a lot we can do.
    goto failout if (!defined($Parent_Inode{$inode}));

    # We may have found multiple directory entries that associate
    # different parent inodes with this inode. Pull out all of the
    # %File_Name entries for this inode which are directory entries
    # and which contain one of the possible parent inodes.
    #
    my @file_keys = ();
    foreach $parent (keys(%{$Parent_Inode{$inode}})) {
	push(@file_keys, grep(m|/2/$parent$|, keys(%{$File_Name{$inode}})));
    }
    
    # Now take all of the @file_keys we pulled out above and march
    # through them in descending order by heuristic score. Recursively
    # call make_best_path() on the parent inode. If we get back a path
    # that goes to the root, then return that. Otherwise return the
    # first unrooted path we get.
    #
    my @paths = ();
    foreach $key (sort { $File_Name{$inode}{$b} <=> $File_Name{$inode}{$a} } @file_keys) {
	($dirname, $type, $parent) = split('/', $key);
	
	$Paths{$parent} = make_best_path($parent) unless (defined($Paths{$parent}));

	return("$Paths{$parent}/$dirname") if ($Paths{$parent} =~ /^\//);
	push(@paths, "$Paths{$parent}/$dirname");
    }
    return($paths[0]) if (scalar(@paths));

    # If we get here then either we don't have a parent inode associated
    # with this inode, or we failed to get any @file_keys entries assocaited
    # with the known parent info we found.
    #
 failout:

    # Grab this directory type entry with the highest heuristic score 
    # for this inode. Bail out if there aren't any directory type entries.
    $dirname = (sort { $File_Name{$inode}{$b} <=> $File_Name{$inode}{$a} } grep(m|/2/|, keys(%{$File_Name{$inode}})))[0];
    return('???') unless (length($dirname));

    # Bail out if we don't have any parent inode info for this inode.
    $dirname =~ s|/.*||;
    return("???/$dirname") if (!defined($Parent_Inode{$inode}));

    # Heuristically try to pick the best parent entry.
    # Recursively call make_best_path().
    # Return whatever we get.
    #
    $parent = (sort { $Parent_Inode{$inode}{$b} <=> $Parent_Inode{$inode}{$a} ||
			  $Max_Dir_Score{$b} <=> $Max_Dir_Score{$a} } keys(%{$Parent_Inode{$inode}}))[0];
    $Paths{$parent} = make_best_path($parent) unless (defined($Paths{$parent}));
    return("$Paths{$parent}/$dirname");
}



# Inode 2 is the root directory. All other inodes <= 10 are reserved.
# The entry length must be positive and <= the amount of data left.
#     It must also be a multiple of 4 bytes.
# The name length must be positive and <= the remaining space in the entry.
# Valid file type values range from 1-8 (8 is a Solaris Door).
# Slashes and nulls are not allowed in file names.
#
sub valid_dir_values {
    my($buffer, $inode, $entry_len, $name_len, $file_type, $file_name) = @_;

    return(undef) unless ($inode == 2 || $inode > 10);
    return(undef) unless ($entry_len <= length($buffer) && $entry_len > 0 && !($entry_len % 4));
    return(undef) unless ($name_len > 0 && $name_len <= ($entry_len - 8));
    return(undef) unless ($file_type > 0 && $file_type < 9);
    return(undef) if ($file_name =~ /[\/\000]/);      # '/' and null not allowed in file names
    return(1);
}


sub parse_dir_block {
    my($buffer) = @_;
    my $namelist = [];

    while (length($buffer)) {

	# Optomistically try to parse the next entry.
        # Bail out of we get invalid data.
	my($inode, $entry_len, $name_len, $file_type) = unpack("LSCC", $buffer);
	my $file_name = substr($buffer, 8, $name_len);
	return([]) unless (valid_dir_values($buffer, $inode, $entry_len, $name_len, $file_type, $file_name));

	# Compute the offset of this entry and then carve the entry
        # out of $buffer, reducing the size of $buffer.
	my $offset = $Block_Size - length($buffer);
	my $this_entry = substr($buffer, 0, $entry_len, '');

	# Add a record to the list of entries we've found so far.
	push(@{$namelist}, { 'filename' => $file_name, 
			     'inode' => $inode,
			     'type' => $file_type,
			     'entrysize' => $entry_len,
			     'namesize' => $name_len,
			     'offset' => $offset });

	# If there's enough slack space in this directory entry,
        # try seeing if there are any deleted directory entries.
	my $extra = $entry_len - $name_len - 8;
	if ($extra >= 12) {
	    my $bytes_to_search = int($extra/4) * 4;
	    my $carved = [];
	    $carved = carve_deleted_entries(substr($this_entry, -$bytes_to_search), 
					    $offset + ($entry_len - $bytes_to_search));
	    push(@{$namelist}, @{$carved}) if (scalar(@{$carved}));    
	}
    }

    return([]) unless (scalar(@{$namelist}) > 1);
    return($namelist);
}


sub carve_deleted_entries {
    my($buffer, $offset) = @_;
    my $namelist = [];

    while (length($buffer) >= 12) {

	# Optomistically try to carve out a directory entry.
	my($inode, $entry_len, $name_len, $file_type) = unpack("LSCC", $buffer);
	my $file_name = substr($buffer, 8, $name_len);

	# If the data we carved is not valid, advance 4 bytes
        # and try again (directory entries are 4 byte aligned).
	if (!valid_dir_values($buffer, $inode, $entry_len, $name_len, $file_type, $file_name)) {
	    $buffer = substr($buffer, 4);
	    $offset += 4;
	    next;
	}

	# Good data? Make a record of what we found.
	push(@{$namelist}, { 'filename' => $file_name, 
			     'inode' => $inode,
			     'type' => $file_type,
			     'entrysize' => $entry_len,
			     'namesize' => $name_len,
			     'offset' => $offset,
			     'carved' => 1});

	# Advance to the next 4 byte aligned location and
        # start over again.
	#
	my $min_len = 8 + $name_len;
	my $remainder = $min_len % 4;
	$min_len += (4 - $remainder) if ($remainder);
	$buffer = substr($buffer, $min_len);
	$offset += $min_len;
    }

    return($namelist);
}


sub parse_htree_root {
    my($buffer) = @_;
    my $i;

    $buffer = substr($buffer, 24);         # chop off "." and ".." entries
    my($reserved, $hash_type, $info_len, $depth, $flags, $max_entries, $num_entries) = unpack("LCCCCSS", $buffer);

    # Reserved bytes must be zero. 
    # Hash type must be < 5.
    # Size of dx_entry records is always 8.
    # Unused flags field should be zero.
    # Can't have more than the stated max entries.
    return(undef) if ($reserved != 0 || $hash_type > 5 || $info_len != 8 || $flags != 0 || $num_entries > $max_entries);
    return(undef) unless ($max_entries == ($Block_Size - 32)/8);   # not fully tested
    print STDERR "SHOOT!\n" if ($depth != 0);
    return(undef) if ($depth != 0);                                # TODO: deal with deep trees

    # Make sure that the block numbers in the htree hash array make sense.
    #
    # There are some shenanigans here. The block number for the "zero hash"
    # is at offset 36 from the front of the hash. Se we throw away the first
    # 32 bytes of the block (24 for the substr() above, and 8 more below).
    # This leaves 4 bytes of $max_entries and $num_entries before the zero
    # hash block number, which makes the unpack() in the loop below work correctly.
    # It's a hack.
    #
    $buffer = substr($buffer, 8);
    for ($i = 0; $i < $num_entries; $i++) {
	my($hash, $block) = unpack("LL", $buffer);
	return(undef) unless ($block <= $num_entries);
	$buffer = substr($buffer, 8);
    }

    return($num_entries);
}


sub output_entry_info {
    my($ref, $blocknum, $dot_inode, $dotdot_inode, $extra) = @_;

    my $allocated = defined($$ref{'carved'}) ? 'n' : 'y';
    print join("\t", $blocknum, 
	             $$ref{'offset'}, 
                     $$ref{'filename'}, 
                     $$ref{'inode'},
	             $File_Type_Char{$$ref{'type'}}, 
                     $$ref{'entrysize'}, 
                     $$ref{'namesize'}, 
                     $allocated,
                     $extra), "\n";
}

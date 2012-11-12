#!/usr/bin/perl -w 
#
use strict; 


if (!defined($ARGV[0])) {

	printf "Usage: \n $0 <patchname.patch> <name-extension> < specfile.spec \n\n";
	exit 1;

}

my $num = 0;
my $inpatch = 0;
my $inpatch2 = 0;
my $applied = 0;
my $patchname = $ARGV[0];
my $extname=$ARGV[1];
while (<STDIN>) {

	if (/(Release:)(.+)/) {
		printf "%s%s%s\n", $1, $2, $extname;
		next;
	}

	if (/Patch(\d+):\s*(.+)/) {
		$num = $1;
		$inpatch = 1;
		if ($patchname =~ /$2/) {
			$applied = 1;
		}
	}
	if ($_ eq "\n" && $inpatch && !$applied) {

		printf "Patch%d: %s\n", ++$num, $patchname;
		$inpatch = 0;
	}

	if (/%patch(\d+)/) {
		$inpatch2 = 1;
	}
	if ($_ eq "\n" && $inpatch2 && !$applied) {
		printf "%%patch%d -p1\n", $num;
		$inpatch2 = 0;

	}

	print $_;

}


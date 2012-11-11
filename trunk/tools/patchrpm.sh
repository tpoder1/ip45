#!/bin/bash

if [ "$1" == "" && "$2" == "" ]; then 
	echo "Usage: $0 <src.rpm name>  <patch-name.patch>"
fi

SRPM="$1"
PATCH="$2"

rpm -ihv $SRPM
cp $PATCH ~/rpmbuild/SOURCES
./updspecfile.pl $(basename $PATCH) ip45 < ~/rpmbuild/SPECS/glibc.spec > /tmp/xx
cd ~/rpmbuild/SPECS/ || exit 1;
cp /tmp/xx glibc.spec
rpmbuild glibc.spec






#!/bin/bash

if [ "$1" == "" ]; then 
	echo "Update source rpm by applying IP45 patches"
	echo "Usage: $0 <src.rpm name>  "
	exit 1
fi

#set -x

SRPM="$1"
SPECF=$(echo $(basename $SRPM)| cut -f1 -d"-")
REV=$(cat ../ID | grep Rev | cut -d' ' -f2)
PATCH="$2"
SUFIX=".ip45_r${REV}"
CDIR=$(pwd)

echo "$SPECF"

rpm -ihv $SRPM

case $SPECF in 
	"glibc")
		PATCH="../patch-glibc/glibc-ip45-resolv.patch"
	;; 
	"kernel")
		PATCH="../patch-linux/linux-kernel-ip45.patch"
		BUILDOPTS="--without kabichk" 
		echo "CONFIG_IP45=y" >> ~/rpmbuild/SOURCES/config-generic
		echo "# CONFIG_IP45_DEBUG is not set" >> ~/rpmbuild/SOURCES/config-generic
	;;
	"tcpdump")
		PATCH="../patch-tcpdump/tcpdump-ip45.patch"
#		echo "CONFIG_IP45=y" >> ~/rpmbuild/SOURCES/config-generic
#		echo "# CONFIG_IP45_DEBUG is not set" >> ~/rpmbuild/SOURCES/config-generic
	;;
	*) 
		echo "Unsupported pkg $SPECF "
		exit 1
	;;
esac


cp $PATCH ~/rpmbuild/SOURCES

cd ~/rpmbuild/SPECS/ || exit 1;
$CDIR//updspecfile.pl $(basename $PATCH) $SUFIX < $SPECF.spec > $SPECF.spec.tmp
mv $SPECF.spec.tmp $SPECF.spec
time rpmbuild -ba --clean $BUILDOPTS $SPECF.spec






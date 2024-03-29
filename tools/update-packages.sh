#!/bin/bash 

# script peridically check SVN and in there is change new 
# packages in packages directory are rebuilt (not part of SVN) 


cd ~

# checkout svn 
svn -q checkout https://ip45.googlecode.com/svn/trunk/ ip45 --username tpoder@cis.vutbr.cz

VERSION=0.$(cat ip45/ID | grep Revision | cut -d" " -f2)

# are there any changes ? 
diff ip45/ID ip45/ID.last 

# exit if there are no changes 
if [ $? == 0 ] ; then 
	echo "no changes..."
	exit 0
fi

cp ID ID.last 

cd ~/ip45


# build ip45d package...
echo "Building ip45d distribution package..."
cd ip45d
make dist 
mv *.tar.gz ~/packages/source/ip45d
cd  ~/packages/source/ip45d/
ln -fs ip45d-${VERSION}.tar.gz ip45d-latest.tar.gz

cd ~/ip45

# build ip45d package...
echo "Building ip45d rpm  binaries..."
rsync -a ~/packages/source/ip45d/ ~/rpmbuild/SOURCES
cd ip45d
rpmbuild -ba ip45d.spec 

cd ~/ip45


# build ip45d package...
echo "Building ip45d windows binaries..."
cd ip45d
make win 
mkdir -p ~/packages/windows/${VERSION}/
mv *.exe ~/packages/windows/${VERSION}/
cd ~/packages/windows
rm latest
ln -fs ${VERSION} latest

cd ~/ip45


# build iptables module package...
echo "Building ipt_ip45bgw packages...."
cd ipt_ip45bgw
make dist 
mv *.tar.gz ~/packages/source/ipt_ip45bgw
cd  ~/packages/source/ipt_ip45bgw/
ln -fs ipt_ip45bgw-${VERSION}.tar.gz ipt_ip45bgw-latest.tar.gz
cd ~/ip45




# rebuild openwrt packages 
#cd tools && ./rebuild-openwrt.sh



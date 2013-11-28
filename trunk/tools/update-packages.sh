#!/bin/bash 

# script peridically check SVN and in there is change new 
# packages in packages directory are rebuilt (not part of SVN) 

cd ~

# checkout svn 
svn -q checkout https://ip45.googlecode.com/svn/trunk/ ip45 --username tpoder@cis.vutbr.cz

# are there any changes ? 
diff ip45/ID ip45/ID.last 

# exit if there are no changes 
if [ $? == 0 ] ; then 
	echo "no changes..."
	exit 0
fi

cd ~/ip45

# build ip45d package...
echo "Building ip45d distribution package..."
cd ip45d
make dist 
mv *.tar.gz ~/packages/source/ip45d

cd ~/ip45

# build iptables module package...
echo "Building ipt_ip45bgw packages...."
cd ipt_ip45bgw
make dist 
mv *.tar.gz ~/packages/source/ipt_ip45bgw

cd ~/ip45


cp ID ID.last 


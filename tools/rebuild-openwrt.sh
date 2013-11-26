#!/bin/bash 

# Script rebuilds OpenWrt pakages 
# The script does: 
# 1. Download the propper version from git repository 
# 2. Prepere build for tarrget platform 
# 3. Copy ip45bgw package definition 
# 4. Build ip45bgw module 
# 5. Repeat 2,3,4 for each architecture 

VERSION="12.09"
NAME="attitude_adjustment"
#TARGETS="adm5120 adm8668 ar7 ar7xx at91 atheros au1000 brcm2708 brcm47xx 
#          brcm63xx cns3xxx cobalt ep93xx ixp4xx kirkwood lantiq malta mcs814x              
#		  mpc52xx mpc83xx omap4 orion ppc40x ramips x86 xburst"
TARGETS="" # detected automatically 

HOMEDIR=$(cd ~ && pwd)
DSTDIR="${HOMEDIR}/packages/openwrt/${NAME}/${VERSION}/"

function build_arch {
	target=$1
	subtarget=$2

	date
 	echo "Building for ${target}_${subtarget}..."	

	rm .config 
	echo "CONFIG_TARGET_${target}=y" >> .config
	echo "CONFIG_TARGET_${target}_${subtarget}=y" >> .config
	echo "CONFIG_PACKAGE_iptables=m" >> .config
	echo "CONFIG_PACKAGE_ip45bgw=m" >> .config
	make defconfig

	make prepare || exit 1
	make package/ip45bgw/compile || exit 1

	mkdir -p ${DSTDIR}/${target}/${subtarget}
	cp bin/${target}/packages/ip45* ${DSTDIR}/${target}/${subtarget}

 	echo "Building for ${target} done."	
	date
}


cd ~/openwrt/ || exit 1
git clone git://git.openwrt.org/${VERSION}/openwrt.git ${VERSION}

cd ${VERSION} || exit 1
mkdir -p package/ip45bgw/
cp -Rv ~/ip45/openwrt/ip45bgw/Makefile package/ip45bgw/

TARGETS=$(ls -1 target/linux | grep -v Makefile | grep -v generic )

mkdir -p logs
rm -f logs/*
rm -rf bin/* 

for target in ${TARGETS}; do 

	subtargets=$(cat target/linux/${target}/Makefile | grep SUBTARGETS | cut -f2 -d=)
	if [ -z "${subtargets}" ]; then 
		subtargets="generic"
	fi 

	for subtarget in $subtargets; do 
		echo  ${target} ${subtarget}  
		build_arch ${target} ${subtarget}  2>&1 | tee logs/${target}_${subtarget}
	done 

done



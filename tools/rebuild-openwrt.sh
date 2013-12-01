#!/bin/bash 

# Script rebuilds OpenWrt pakages 
# The script does: 
# 1. Download the propper version from git repository 
# 2. Prepere build for tarrget platform 
# 3. Copy ip45bgw package definition 
# 4. Build ip45bgw module 
# 5. Repeat 2,3,4 for each architecture 


HOMEDIR=$(cd ~ && pwd)
DSTDIR="${HOMEDIR}/packages/openwrt/"
INDEX="./staging_dir/host/bin/ipkg-make-index"

function build_target {
	pkgdir=$1
	target=$2
	subtarget=$3

	date
 	echo "Building for ${target}..."	

	echo "" > .config
	echo "CONFIG_TARGET_${target}=y" >> .config
	if [ "$subtarget" != "" ]; then
		echo "CONFIG_TARGET_${target}_${subtarget}=y" >> .config
	fi
	echo "CONFIG_PACKAGE_iptables=m" >> .config
	echo "CONFIG_PACKAGE_ip45bgw=m" >> .config
	make defconfig > /dev/null 

	make prepare || exit 1
	make package/ip45bgw/compile V=s || exit 1

	if [ -f bin/${target}/packages/ip45* ] 
	then 
		mkdir -p ${pkgdir}
		cp bin/${target}/packages/*ip45* ${pkgdir}
		./staging_dir/host/bin/ipkg-make-index ${pkgdir} > "${pkgdir}/Packages"
		gzip < "${pkgdir}/Packages" > "${pkgdir}/Packages.gz"
	else 
		echo "The package was not built"
	fi 

 	echo "Building for ${target}_${subtarget} done."	
	date
}

function build_release {
	NAME=$1
	VERSION=$2
	GITREPO=$3
	SUBTARGETS=$4  # build all subtargets ? 

	echo "****************************"
	echo "* $1 $2 $3 "
	echo "****************************"

	cd ~/openwrt/ || exit 1
	git clone ${GITREPO} ${VERSION}

	cd ${VERSION} || exit 1
	mkdir -p package/ip45bgw/
	cp -Rv ~/ip45/openwrt/ip45bgw/Makefile package/ip45bgw/

	mkdir -p logs
	rm -f logs/*
	rm -rf bin/* 

	TARGETS=$(ls -1 target/linux | grep -v Makefile | grep -v generic )

	for target in ${TARGETS}; do 

			if [ "${SUBTARGETS}" == "no" ]; then 
			# single target
			echo  ${target}   
			pkgdir="${DSTDIR}/${NAME}/${VERSION}/${target}/packages"
			build_target ${pkgdir} ${target} 2>&1 | tee logs/${target}
		else 
			# multiple targets 	
			subtargets=$(cat target/linux/${target}/Makefile | grep SUBTARGETS | cut -f2 -d=)
			if [ -z "${subtargets}" ]; then 
				subtargets="generic"
			fi 

			for subtarget in $subtargets; do 
				echo  ${target} ${subtarget}  
				pkgdir="${DSTDIR}/${NAME}/${VERSION}/${target}/${subtarget}/packages"
				build_target ${pkgdir} ${target} ${subtarget} 2>&1 | tee logs/${target}_${subtarget}
			done 
		fi
	done
}

build_release "attitude_adjustment" "12.09" "git://git.openwrt.org/12.09/openwrt.git" "yes"
build_release "barrier_breaker" "trunk" "git://git.openwrt.org/openwrt.git" "no"



# The script get patch from the kernel source 

O=linux-2.6.32-131.17.1.el6.orig
U=linux-2.6.32-131.17.1.el6.x86_64
P=linux-kernel-ip45.patch

#cd $U && make clean && cd ..
rm $P
diff --exclude *.mo \
	--exclude *.cmd \
	-rupN $O/net $U/net >> $P

diff --exclude include/asm/* \
	--exclude asm-offsets.h \
	--exclude auto.conf \
	--exclude auto.conf.cmd \
	--exclude autoconf.h \
	--exclude utsrelease.h \
	--exclude bounds.h \
	--exclude kernel.release \
	--exclude include/linux/version.h \
	-rupN $O/include $U/include >> $P


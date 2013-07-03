

O=tcpdump
U=tcpdump-ip45
P=tcpdump-ip45.patch

#cd $U && make clean && cd ..
rm $P
diff --exclude autom4te.cache \
	--exclude *.o \
	--exclude config.* \
	--exclude Makefile \
	--exclude Makefile-* \
	--exclude *.orig \
	--exclude version.c \
	--exclude tcpdump.1 \
	--exclude tcpdump \
	--exclude print-ip45.c \
	--exclude ip45.h \
	-rupN $O $U >> $P




O=tcpdump-4.1.1
U=tcpdump-4.1.1-ip45
P=tcpdump-ip45.patch

#cd $U && make clean && cd ..
rm $P
diff --exclude autom4te.cache \
	--exclude *.o \
	--exclude config.* \
	--exclude Makefile \
	--exclude Makefile-* \
	--exclude version.c \
	--exclude tcpdump.1 \
	--exclude tcpdump \
	-rupN $O $U >> $P



#
# Thos module shoul be able to CROSS_PLATFORM compile. The following 
# command compiles the module on mips platfom for openwrt 
#
# make KPATH=../kernel/linux-3.5.7 ARCH=mips CROSS_COMPILECROSS_COMPILE=mips64-linux-gnu-
#
#


obj-m := ipt_ip45bgw.o

KVERSION := $(shell uname -r)
PLATFORM := $(shell uname -m)
PATH := /lib/modules/$(KVERSION)/build

#ARCH=mip
#CROSS_COMPILE=mips-openwrt
#KPATH := /root/rpmbuild/linux-2.6.24
#KPATH := /root/rpmbuild/DD-WRT/src/tmp/linux-2.6.23

all:	libipt_ip45bgw.so
	$(MAKE) -C $(KPATH) M=$(PWD) modules


libipt_ip45bgw.so: libipt_ip45bgw.o
	$(CC) -shared -o $@ $<

libipt_ip45bgw.o: libipt_ip45bgw.c ipt_ip45bgw.h Makefile
	$(CC) $(CFLAGS) -Wall -pipe -D_INIT=libipt_ip45bgw_init -DPIC -fPIC -g -O2 -o $@ -c $<

clean:
	$(MAKE) -C $(KPATH) M=$(PWD) clean
	rm -f *.so
	rm -f *.cmd
	rm -f *~

install:
	install ipt_ip45bgw.ko /lib/modules/$(KVERSION)
ifeq ($(PLATFORM),x86_64)
	install libipt_ip45bgw.so /lib64/xtables
else
	install libipt_ip45bgw.so /lib/xtables
endif


obj-m := ipt_IP45.o
KVERSION := $(shell uname -r)
KPATH := /lib/modules/$(KVERSION)/build
IPTABLES_VERSION := $(shell (/sbin/iptables --version 2>&- || ip6tables --version)|sed 's/^.*\([[:digit:]]\+\.[[:digit:]]\+\.[[:digit:]]\+\).*/\1/')
IPTABLES_VERSION_CODE := $(shell echo $$(( $$(echo $(IPTABLES_VERSION)|sed 's/^.*\([[:digit:]]\+\)\.\([[:digit:]]\+\)\.\([[:digit:]]\+\).*/\1 * 65536 + \2 * 256 + \3/') )))
ifeq ($(DEBUG),1)
EXTRA_CFLAGS := -DDEBUG
endif

all:	libipt_IP45.so
	$(MAKE) -C $(KPATH) M=$(PWD) modules

libipt_IP45.so: libipt_IP45.o
	gcc -shared -o $@ $<

libipt_IP45.o: libipt_IP45.c ipt_IP45.h Makefile
	gcc $(CFLAGS) -DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\" -DIPTABLES_VERSION_CODE=$(IPTABLES_VERSION_CODE) -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 -D_REENTRANT -Werror -Wall -Waggregate-return -Wmissing-declarations -Wmissing-prototypes -Wredundant-decls -Wshadow -Winline -pipe -DXTABLES_LIBDIR=\"/usr/local/libexec/xtables\" -D_INIT=libipt_ip45_init -DPIC -fPIC -g -O2 -o $@ -c $<

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -f *.so
	rm -f *~

install: /lib64/xtables/libipt_IP45.so

/lib64/xtables/libipt_IP45.so: libipt_IP45.so
	cp $< $@

README.txt: README.dbk
	xmlto text README.dbk

README.html: README.dbk
	xmlto xhtml-nochunks README.dbk


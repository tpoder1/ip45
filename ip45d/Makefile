
revision = $(shell cat ../ID | grep Revision | cut -d" " -f2)
version=0.$(revision)
distdir = ip45d-$(version)
prefix :=/

main:
	gcc -I../common -I. -O3 -DPKG_VERSION=\"$(version)\" -Wall -o ip45d ip45d.c inet_ntop45.c session_table.c

win:
	i686-pc-mingw32-gcc -DPKG_VERSION=\"$(version)\"  ip45d.c inet_ntop45.c session_table.c compat_win.c -o ip45d.exe -I ../common -DWIN32 -DWIN32_LEAN_AND_MEAN -D__LITTLE_ENDIAN__ -Wall -lkernel32 -lwsock32 -lws2_32
	i686-pc-mingw32-gcc  ip45serv.c -o ip45serv.exe -DWIN32 -D_UNICODE -DUNICODE -Wall -lkernel32 -lwsock32 -lws2_32
	makensis ip45.nsi 

clean:
	rm -f ip45d *.exe  

install:
	mkdir -p $(prefix)/usr/sbin
	cp ip45d $(prefix)/usr/sbin
	mkdir -p $(prefix)/etc/rc.d/init.d/
	cp ip45d-init-d $(prefix)/etc/rc.d/init.d/ip45d

dist:  
	mkdir $(distdir)
	cp -R ../common/ip45.h Makefile ip45d-init-d *.c *.h *.nsi *.bat $(distdir)
	find $(distdir) -name .svn -delete
	tar czf $(distdir).tar.gz $(distdir)
	rm -rf $(distdir)



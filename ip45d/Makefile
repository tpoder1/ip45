
version = $(shell cat ../ID | grep Revision | cut -d" " -f2)
distdir = ip45d-0.$(version)

main:
	gcc -I../common -O3 -Wall -o ip45d ip45d.c inet_ntop45.c session_table.c

win:
	i686-pc-mingw32-gcc  ip45d.c inet_ntop45.c session_table.c compat_win.c -o ip45d.exe -I ../common -DWIN32 -DWIN32_LEAN_AND_MEAN -D__LITTLE_ENDIAN__ -Wall -lkernel32 -lwsock32 -lws2_32
	i686-pc-mingw32-gcc  ip45serv.c -o ip45serv.exe -DWIN32 -D_UNICODE -DUNICODE -Wall -lkernel32 -lwsock32 -lws2_32
	makensis ip45.nsi 

clean:
	rm -f ip45d *.exe  

dist:  
	mkdir $(distdir)
	cp -R ../common/ip45.h Makefile *.c *.h *.nsi *.bat $(distdir)
	find $(distdir) -name .svn -delete
	tar czf $(distdir).tar.gz $(distdir)
	rm -rf $(distdir)



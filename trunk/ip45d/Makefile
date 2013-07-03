
distdir = ip45d-0.1

main:
	gcc -I../common -pthread -O3 -Wall -o ip45d ip45d.c inet_ntop45.c  session_table.c

clean:
	rm ip45d

dist:  
	mkdir $(distdir)
	cp -R ../common/ip45.h Makefile *.c *.h $(distdir)
	find $(distdir) -name .svn -delete
	tar czf $(distdir).tar.gz $(distdir)
	rm -rf $(distdir)


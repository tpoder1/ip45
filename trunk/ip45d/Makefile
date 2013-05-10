
distdir = ip45d-0.1

main:
	gcc -O3 -Wall -o ip45d ip45d.c inet_ntop45.c ip45_session_tables.c 

clean:
	rm ip45d

dist:  
	mkdir $(distdir)
	cp -R Makefile ip45d.c inet_ntop45.c inet_ntop45.h ip45_session_tables.c $(distdir)
	find $(distdir) -name .svn -delete
	tar czf $(distdir).tar.gz $(distdir)
	rm -rf $(distdir)


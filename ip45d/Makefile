
distdir = ip45d-0.1

main:
	gcc -lpcap -pthread -O3 -Wall -o ip45d ip45d.c 

clean:
	rm ip45d

dist:  
	mkdir $(distdir)
	cp -R Makefile ip45d.c $(distdir)
	find $(distdir) -name .svn -delete
	tar czf $(distdir).tar.gz $(distdir)
	rm -rf $(distdir)


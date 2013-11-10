/*
 * IP45 support for tcpdump 
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/print-ip45.c,v 1.0 2012-11-05  $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "ip.h"
#include "ip45.h"

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"

/* const char *
 * inet_ntop45(src, dst, size)
 *	format an IPv45 address
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Tomas Podermanski, 2012.
 */
const char *
inet_ntop45_mark(src, dst, size)
	const char *src;
	char *dst;
	socklen_t size;
{
	char tmp[16 * sizeof "255." - 1], *tp;
	int octet;

	for (octet = 0; octet < 16 - 4; octet++) {
		if (src[octet] != 0) 
			break;
	}

	tp = tmp;
	for (; octet < 16 ; octet++) {
		tp += sprintf(tp, "%u", src[octet] & 0xFF);
		if ( octet != 15 ) {
			*tp++ = '.';
		}
	}
	*tp++ = '\0';

	if ((socklen_t)(tp - tmp) > size) {
		return NULL;
	}
	return strcpy(dst, tmp);
}

int
ip45_print(register const u_char *bp, int length)
{
	register const struct ip45hdr *ip45 = (struct ip45hdr *)bp;
	char s_d45addr[70], s_s45addr[70];
	char s_daddr[70], s_saddr[70];
	struct in45_addr s45addr, d45addr;
	int x; 

	if ( length < sizeof(struct ip45hdr) ) {
		fputs("[|IP45]", stdout);
		return -1;
	}


	stck45_to_in45(&s45addr, (void *)&ip45->saddr, &ip45->s45stck, ip45->s45mark);
	stck45_to_in45(&d45addr, (void *)&ip45->daddr, &ip45->d45stck, ip45->d45mark);

/*
	printf("DEBUG1:");	
	for (x = 0; x < sizeof(struct in45_stck); x++) {
		printf("%02x ", ((char *)&ip45->d45stck)[x] & 0xFF);
	}
	printf("\n");	

	printf("DEBUG2:");	
	for (x = 0; x < sizeof(struct in45_addr); x++) {
		printf("%02x ", ((char *)&d45addr)[x] & 0xFF);
	}
	printf("\n");	
*/

	inet_ntop45_mark((char *)&s45addr, &s_s45addr, sizeof(s_s45addr));
	inet_ntop45_mark((char *)&d45addr, &s_d45addr, sizeof(s_d45addr));

	if (! vflag) {
		printf("\b45 [%08lx.] %s > %s ", 
				(unsigned long)ip45->sid.s45_sid32[0],
				s_s45addr, s_d45addr);
	} else {
		inet_ntop(AF_INET, &ip45->saddr, s_saddr, sizeof(s_saddr));
		inet_ntop(AF_INET, &ip45->daddr, s_daddr, sizeof(s_daddr));

		printf("IP45 %s:%d > %s:%d [%016lx%016lx] %s#%d > %s#%d ", 
				s_saddr, ntohs(ip45->ip45sp), 
				s_daddr, ntohs(ip45->ip45dp),
				(unsigned long)ip45->sid.s45_sid64[0],
				(unsigned long)ip45->sid.s45_sid64[1],
				s_s45addr, ip45->s45mark, s_d45addr, ip45->d45mark);
		if (vflag > 1) {
			printf("45le=%d 45ze=0x%04x 45check=0x%04x", ntohs(ip45->ip45le), ip45->ip45ze, ip45->check45);
		}
		
		printf("\n      ");
	}

	return 1;
}



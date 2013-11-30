

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sys/param.h>
#include <sys/types.h>
#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
//#include <ws2def.h>
#include <ws2tcpip.h>
#else 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#endif 



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
extern const char *
inet_ntop45(src, dst, size)
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


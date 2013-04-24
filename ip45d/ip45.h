/*
*  IP45 - basic structures 
*  Tomas Podermanski, tpoder@cis.vutbr.cz 
*/

#ifndef _IP45_H
#define _IP45_H "2013-04-16 01"
#endif

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#include <winsock2.h>
#endif 

/* #include <linux/types.h> */
/* #include <asm/byteorder.h> */

#ifdef WIN32 
typedef short sa_family_t;
#endif


#ifndef IPPROTO_IP45_DEFINED
enum {
  IPPROTO_IP45 = 155,   /* IP 4.5  - IP45          */
};
#endif

/* IP45 address structure */
struct in45_addr
{
    union
    {
        uint8_t        u45_addr8[16];
        uint16_t      u45_addr16[8];
        uint32_t      u45_addr32[4];
    } in45_u;
#define s45_addr         in45_u.u45_addr8
#define s45_addr16       in45_u.u45_addr16
#define s45_addr32       in45_u.u45_addr32
};

/* IP45 header (standart IP header with no options + extra IP45 header */
struct ip45hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t	sver:4,					/* sub version, always set to 5 */
		mver:4;					/* major version, always set to 4 */
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t	mver:4,
 		sver:4;	
#else
#error	"Byte order not detected"
#endif
	uint8_t	tos;	
	uint16_t tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;	/* have to always be set to IPPROTO_IP45 */ 
	uint16_t	check1;
	uint32_t	saddr;
	uint32_t	daddr;
	/* extended header for IP4.5 is presented here */
	uint8_t	nexthdr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t	flags:4,
			dmark:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t	dmark:4,
	  		flags:4;				
#else
#error	"Byte order not detected"
#endif
	uint16_t	check2;
	struct in45_addr	s45addr;
	struct in45_addr	d45addr;
	uint64_t	sid;  
	/* no IP options allowed in IP4.5 */
};

struct sockaddr_in45 {
	sa_family_t			sin45_family;	/* Address family		*/
	uint16_t				sin45_port;		/* Port number			*/
	struct in45_addr	sin45_addr;

};

/* return the pointer to the begin of the IP address (find first non 0 octet)*/
static inline void *ip45_addr_begin(const struct in45_addr *addr)
{
	uint8_t *p;

	for (p = (uint8_t *)addr; p - (uint8_t*)addr < sizeof(struct in45_addr) - sizeof(uint32_t); p++) {
		if ((uint8_t)*p != 0x0) break;
	}
	return p;
}



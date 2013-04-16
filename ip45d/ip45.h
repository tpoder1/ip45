/*
*  IP45 - Extended IP protocol 
*  Tomas Podermanski, tpoder@cis.vutbr.cz 
*/

#ifndef _NET_IP45_H
#define _NET_IP45_H "2012-11-05 01"
#endif

/* #include <linux/types.h> */
/* #include <asm/byteorder.h> */



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
#if defined(__LITTLE_ENDIAN__)
	uint8_t	sver:4,					/* sub version, always set to 5 */
		mver:4;					/* major version, always set to 4 */
#elif defined (__BIG_ENDIAN__)
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
#if defined(__LITTLE_ENDIAN__)
	uint8_t	flags:4,
			dmark:4;
#elif defined (__BIG_ENDIAN__)
	uint8_t	dmark:4,
	  		flags:4;				
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



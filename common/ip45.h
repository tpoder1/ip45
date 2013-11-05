/*
*  IP45 - Extended IP protocol 
*  Tomas Podermanski, tpoder@cis.vutbr.cz 
*/

#ifndef _NET_IP45_H
#define _NET_IP45_H "2013-11-05 01"

#ifdef __linux 
#include <linux/types.h>
#include <asm/byteorder.h>
//#include <netinet/in.h>
//#include <net/inet_sock.h>
//#include <endian.h>
#ifdef __LITTLE_ENDIAN 
#define __LITTLE_ENDIAN__
#endif
#ifdef __BIG_ENDIAN 
#define __BIG_ENDIAN__
#endif
#endif /* #ifdef linux */

#ifdef WIN32
typedef unsigned short sa_family_t;
#endif


#define IP45_COMPAT_UDP_PORT 4

/* IP45 address structure */
struct in45_addr
{
    union
    {
        uint8_t       u45_addr8[16];
        uint16_t      u45_addr16[8];
        uint32_t      u45_addr32[4];
    } in45_u;
#define s45_addr         in45_u.u45_addr8
#define s45_addr16       in45_u.u45_addr16
#define s45_addr32       in45_u.u45_addr32
};

/* IP45 address structure */
struct in45_stck
{
    union
    {
        uint8_t       u45_stck8[12];
        uint16_t      u45_stck16[6];
        uint32_t      u45_stck32[3];
    } in45s_u;
#define s45_stck         in45s_u.u45_stck8
#define s45_stck16       in45s_u.u45_stck16
#define s45_stck32       in45s_u.u45_stck32
};

/* IP45 SID - session ID */
struct in45_sid
{
    union
    {
        uint8_t       u45_sid8[16];
        uint16_t      u45_sid16[8];
        uint32_t      u45_sid32[4];
        uint64_t      u45_sid64[2];
    } sid45_u;
#define s45_sid         sid55_u.u45_sid8
#define s45_sid16       sid45_u.u45_sid16
#define s45_sid32       sid45_u.u45_sid32
#define s45_sid64       sid45_u.u45_sid64
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
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;	/* have to always be set to IPPROTO_UDP */ 
	uint16_t	check1;
	uint32_t	saddr;
	uint32_t	daddr;
	/* compatibility header for UDP */
	uint16_t  ip45sp;		// 45
	uint16_t  ip45dp;		// 45
	uint16_t  ip45le;		// XX
	uint16_t  ip45ze;		// zeros 
	/* extended header for IP4.5 is presented here */
	uint8_t	nexthdr;
#if defined(__LITTLE_ENDIAN__)
	uint8_t	d45mark:4,
			s45mark:4;
#elif defined (__BIG_ENDIAN__)
	uint8_t	s45mark:4,
	  		d45mark:4;				
#else
#error	"Byte order not detected"
#endif
	uint16_t	check45;
	struct in45_stck	s45stck;
	struct in45_stck	d45stck;
	struct in45_sid		sid;  
	/* no IP options allowed in IP4.5 */
};

#pragma pack(push, 1)

/* IP45 without p1 and p2 part (IP, UDP) */
struct ip45hdr_p3 {
	uint8_t	nexthdr;
#if defined(__LITTLE_ENDIAN__)
	uint8_t	d45mark:4,
			s45mark:4;
#elif defined (__BIG_ENDIAN__)
	uint8_t	s45mark:4,
	  		d45mark:4;				
#else
#error	"Byte order not detected"
#endif
	uint16_t	check45;
	struct in45_stck	s45stck;
	struct in45_stck	d45stck;
	struct in45_sid		sid;  
	/* no IP options allowed in IP4.5 */
};

#pragma pack(pop)

struct sockaddr_in45 {
	sa_family_t			sin45_family;	/* Address family		*/
	uint16_t			sin45_port;		/* Port number			*/
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

/* detect whether packet is valid IP45 packet */
static inline int is_ip45_pkt(const struct ip45hdr *ip45h)
{
	return (ip45h->mver == 4 && \
			ip45h->sver == 5 && \
			ip45h->protocol == IPPROTO_UDP && \
			( ip45h->ip45sp == htons(IP45_COMPAT_UDP_PORT) || 
			ip45h->ip45dp == htons(IP45_COMPAT_UDP_PORT)) );
}



/* converts IPv4 and IP45stack address into single IP45 address */
/* output :  in45 */
/* input  :  stck45, in, mark */
static inline void stck45_to_in45(
	const struct in45_addr *in45, 
	const struct in_addr *in, 
	const struct in45_stck *stck45, 
	const uint8_t mark) 
{
	/* clean ip45 addr */
	memset((void *)in45, 0, sizeof(struct in45_addr));

	/* IPv4 address part */
	memcpy((void *)in45 + (sizeof(struct in45_addr) - mark - sizeof(struct in_addr)), 
			(void *)in, sizeof(struct in_addr));

	if (mark == 0) return;

	/* stack part */
	memcpy((void *)in45 + (sizeof(struct in45_addr) - mark), 
			(void *)stck45 + (sizeof(struct in45_stck) - mark),
			 mark);
}

/* converts IP45 address into  IP45stack address and single IPv4 address */
/* output :  in, stck45, mark (return value)*/
/* input:    in45 */
static inline uint8_t in45_to_stck45(
	const struct in_addr *in, 
	const struct in45_stck *stck45, 
	const struct in45_addr *in45) 
{

	/* get begin of the IP45 address */
	void *bgn = ip45_addr_begin((void *)in45);

	/* get mark */
	uint8_t mark = 12 - (bgn - (void *)in45);

	/* IPv4 address part */
	memcpy((void *)in, bgn, sizeof(struct in_addr));

	/* cleanup and set stack part */
	memset((void *)stck45, 0, sizeof(struct in45_stck));

	if (mark == 0) return 0;

	memcpy((void *)stck45 + (sizeof(struct in45_stck) - mark), 
			bgn + sizeof(struct in_addr),  mark);

	return mark;
}

#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct ip45hdr *ip45_hdr(const struct sk_buff *skb)
{
	return (struct ip45hdr *)skb_network_header(skb);
}

static inline int is_ip45_skb(const struct sk_buff *skb)
{
	return (ip45_hdr(skb)->mver == 4 && \
			ip45_hdr(skb)->sver == 5 && \
			ip45_hdr(skb)->protocol == IPPROTO_UDP && \
			ip45_hdr(skb)->ip45dp == htons(IP45_COMPAT_UDP_PORT));
}

#endif	/* __LERNEL__ */

#endif	/* _NET_IP45_H */


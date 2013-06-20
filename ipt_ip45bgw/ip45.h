/*
*  IP45 - Extended IP protocol 
*  Tomas Podermanski, tpoder@cis.vutbr.cz 
*/

#ifndef _NET_IP45_H
#define _NET_IP45_H "2013-06-20 01"

#include <linux/types.h>
#include <asm/byteorder.h>
#include <net/inet_sock.h>

#ifndef IPPROTO_IP45_DEFINED
enum {
  IPPROTO_IP45 = 155,	/* IP 4.5  - IP45          */
  IPPROTO_CDP = 156,	/* IP 4.5  - Content Delivery Protocol */
};
#define IPPROTO_IP45_DEFINED 1
#endif

#define IP45_COMPAT_UDP_PORT 45

/* IP45 address structure */
struct in45_addr
{
    union
    {
        __u8        u45_addr8[16];
        __be16      u45_addr16[8];
        __be32      u45_addr32[4];
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
        __u8        u45_stck8[12];
        __be16      u45_stck16[6];
        __be32      u45_stck32[3];
    } in45s_u;
#define s45_stck         in45s_u.u45_stck8
#define s45_stck16       in45s_u.u45_stck16
#define s45_stck32       in45s_u.u45_stck32
};

/* IP45 header (standart IP header with no options + extra IP45 header */
struct ip45hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	sver:4,					/* sub version, always set to 5 */
			mver:4;					/* major version, always set to 4 */
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	mver:4,
 			sver:4;	
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;	
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;	/* have to always be set to IPPROTO_UDP */ 
	__sum16	check1;
	__be32	saddr;
	__be32	daddr;
	/* compatibility header for UDP */
	__be16  ip45sp;		// 45
	__be16  ip45dp;		// 45
	__be16  ip45le;		// XX
	__be16  ip45ze;		// zeros 
	/* extended header for IP4.5 is presented here */
	__u8	nexthdr;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	d45mark:4,
			s45mark:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	s45mark:4,
	  		d45mark:4;				
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__sum16	check45;
	struct in45_stck	s45stck;
	struct in45_stck	d45stck;
	__be64	sid;  
	/* no IP options allowed in IP4.5 */
};

struct sockaddr_in45 {
	sa_family_t			sin45_family;	/* Address family		*/
	__be16				sin45_port;		/* Port number			*/
	struct in45_addr	sin45_addr;

};

/* return the pointer to the begin of the IP address (find first non 0 octet)*/
static inline void *ip45_addr_begin(const struct in45_addr *addr)
{
	__u8 *p;

	for (p = (__u8 *)addr; p - (__u8*)addr < sizeof(struct in45_addr) - sizeof(__be32); p++) {
		if ((__u8)*p != 0x0) break;
	}
	return p;
}

/* detect whether packet is valid IP45 packet */
static inline int is_ip45_pkt(const struct ip45hdr *ip45h)
{
	return (ip45h->mver == 4 && \
			ip45h->sver == 5 && \
			ip45h->protocol == IPPROTO_UDP && \
			ip45h->ip45dp == htons(IP45_COMPAT_UDP_PORT));
}


#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct ip45hdr *ip45_hdr(const struct sk_buff *skb)
{
	return (struct ip45hdr *)skb_network_header(skb);
}

static inline int is_ip45(const struct sk_buff *skb)
{
	return (ip45_hdr(skb)->mver == 4 && \
			ip45_hdr(skb)->sver == 5 && \
			ip45_hdr(skb)->protocol == IPPROTO_UDP && \
			ip45_hdr(skb)->ip45dp == IP45_COMPAT_UDP_PORT);
}

/* converts IPv4 and IP45stack address into single IP45 address */
/* output :  in45 */
/* input  :  stck45, in, mark */
static inline void stck45_to_in45(
	const struct in45_addr *in45, 
	const struct in_addr *in, 
	const struct in45_stck *stck45, 
	const __u8 *mark) 
{
	/* clean ip45 addr */
	memset((void *)in45, 0, sizeof(struct in45_addr));

	/* IPv4 address part */
	memcpy((void *)in45 + (sizeof(struct in45_addr) - *mark - sizeof(struct in_addr)), 
			(void *)in, sizeof(struct in_addr));

	/* stack part */
	memcpy((void *)in45 + (sizeof(struct in45_addr) - *mark), 
			(void *)stck45, *mark);
}

/* converts IP45 address into  IP45stack address and single IPv4 address */
/* output :  in, stck45, mark (return value)*/
/* input:    in45 */
static inline __u8 in45_to_stck45(
	const struct in_addr *in, 
	const struct in45_stck *stck45, 
	const struct in45_addr *in45) 
{

	/* get begin of the IP45 address */
	void *bgn = ip45_addr_begin((void *)in45);

	/* get mark */
	__u8 mark = 12 - (bgn - (void *)in45);

	/* IPv4 address part */
	memcpy((void *)in, bgn, sizeof(struct in_addr));

	/* cleanup and set stack part */
	memset((void *)stck45, 0, sizeof(struct in45_stck));
	memcpy((void *)stck45 + (sizeof(struct in45_stck) - mark), 
			bgn + sizeof(struct in_addr),  mark);

	return mark;
}


struct cdp_sock {
    /* inet_sock has to be the first member */
    struct inet_sock inet;
    int      pending;   /* Any pending frames ? */
    unsigned int     corkflag;  /* Cork is required */
    __u16        encap_type;    /* Is this an Encapsulation socket? */
    /*
 *      * Following member retains the information to create a UDP header
 *           * when the socket is uncorked.
 *                */
    __u16        len;       /* total length of pending frames */
    /*
 *      * Fields specific to UDP-Lite.
 *           */
    __u16        pcslen;
    __u16        pcrlen;
/* indicator bits used by pcflag: */
    __u8         pcflag;        /* marks socket as UDP-Lite if > 0    */
    __u8         unused[3];
    /*
 *      * For encapsulation sockets.
 *           */
    int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);
};

static inline struct cdp_sock *cdp_sk(const struct sock *sk)
{
    return (struct cdp_sock *)sk;
}




#endif

#endif	/* _NET_IP45_H */


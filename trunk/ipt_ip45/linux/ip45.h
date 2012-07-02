

#include <linux/types.h>
#include <asm/byteorder.h>

/*
*  IPv4.5
*  
*/

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

struct ip45hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 minorv:4,				/* minor version, always set to 5 */
		majorv:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	majorv:4,
  		minorv:4;					/* minor version, always set to 5 */
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;	
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;	/* have to always be set to IPPROTO_IP45 */ 
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/* extended header for IP4.5 is presented here */

	__u8	nexthdr;
	__u8	flags;
	__u8	retlen;
	__u8	fwdlen;
	struct in45_addr	retpath;
	struct in45_addr	fwdpath;
	__be32	sid;  

	/* no IP options allowed in IP4.5 */
};

struct sockaddr_in45 {
	sa_family_t			sin45_family;	/* Address family		*/
	__be16				sin45_port;	/* Port number			*/
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


#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct ip45hdr *ip45_hdr(const struct sk_buff *skb)
{
	return (struct ip45hdr *)skb_network_header(skb);
}

static inline int is_ip45(const struct sk_buff *skb)
{
	return (ip45_hdr(skb)->majorv == 4 && \
			ip45_hdr(skb)->minorv == 5 && \
			ip45_hdr(skb)->protocol == IPPROTO_IP45);
}
#endif



#include <ws2tcpip.h>

#define IFNAMSIZ 1024


/*
struct in6_addr {
           uint8_t  s6_addr[16]; 
   };
*/



struct ip6_hdr {
      union {
        struct ip6_hdrctl {
          uint32_t ip6_un1_flow;   /* 24 bits of flow-ID */
          uint16_t ip6_un1_plen;   /* payload length */
          uint8_t  ip6_un1_nxt;    /* next header */
          uint8_t  ip6_un1_hlim;   /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;       /* 4 bits version, 4 bits priority */
      } ip6_ctlun;
      struct in6_addr ip6_src;      /* source address */
      struct in6_addr ip6_dst;      /* destination address */
    };

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

#define IPPROTO_HOPOPTS        0 /* IPv6 Hop-by-Hop options */
#define IPPROTO_IPV6          41 /* IPv6 header */
#define IPPROTO_ROUTING       43 /* IPv6 Routing header */
#define IPPROTO_FRAGMENT      44 /* IPv6 fragmentation header */
#define IPPROTO_ESP           50 /* encapsulating security payload */
#define IPPROTO_AH            51 /* authentication header */
#define IPPROTO_ICMPV6        58 /* ICMPv6 */
#define IPPROTO_NONE          59 /* IPv6 no next header */
#define IPPROTO_DSTOPTS       60 /* IPv6 Destination options */


struct tcphdr
{
    uint16_t   th_sport;           /* source port */
    uint16_t   th_dport;           /* destination port */
    uint32_t   th_seq;             /* sequence number */
    uint32_t   th_ack;             /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t    th_x2:4;            /* (unused) */
    uint8_t    th_off:4;           /* data offset */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t    th_off:4;           /* data offset */
    uint8_t    th_x2:4;            /* (unused) */
#else 
#error "Byte order not detected"
#endif
    uint8_t    th_flags;
    #define    TH_FIN        0x01
    #define    TH_SYN        0x02
    #define    TH_RST        0x04
    #define    TH_PUSH       0x08
    #define    TH_ACK        0x10
    #define    TH_URG        0x20
    #define    TH_ECE        0x40
    #define    TH_CWR        0x80
    uint16_t   th_win;             /* window */
    uint16_t   th_sum;             /* checksum */
    uint16_t   th_urp;             /* urgent pointer */
};

struct udphdr {
	uint16_t   uh_sport;
	uint16_t   uh_dport;
	uint16_t   uh_len;
	uint16_t   uh_sum;
};


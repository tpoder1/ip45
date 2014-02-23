/*

  IP45 Project - http://ip45.org

  Copyright (C) 2012 - 2014,  Tomas Podermanski

  This code can be redistributed and/or modified under the terms of 
  the GNU General Public License as published by the Free Software 
  Foundation, either version 3 of the License, or (at your option) 
  any later version, see <http://www.gnu.org/licenses/>.

*/


#include "ip45d.h"
#include "ip45d_common.h"
#include "session_table.h"
#include "inet_ntop45.h"
#include <icmp6.h>


uint16_t inet_cksum(addr, len) 
char *addr; 
int len;
{
    register int nleft = (int)len;
    register uint16_t *w = (uint16_t *)addr;
    uint16_t answer = 0;
    register int sum = 0;


    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *)w ;
        sum += answer;
    }

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

/* generates the random SID */
void mksid(struct in45_sid *sid) {
	int i; 

	if  ( RAND_MAX < 0xFFFF) {
		for (i = 0 ; i < sizeof(sid->s45_sid16) / sizeof(uint16_t); i++) {
			sid->s45_sid16[i] = rand();
		}
	} else {
		for (i = 0 ; i < sizeof(sid->s45_sid32) / sizeof(uint32_t); i++) {
			sid->s45_sid32[i] = rand();
		}
	}
}


/* process IP45 packet and prepare it as IPv6 packet*/
/* !1 - we expect that ipv6 buffer is big enough to handle data */
ssize_t ip45_to_ipv6(struct sockaddr_in *peer45_addr, char *ip45pkt, ssize_t len45, char *ip6pkt) {

	struct ip45hdr_p3 *ip45h = (struct ip45hdr_p3 *)ip45pkt;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)ip6pkt;
	char *ip45data = ip45pkt + sizeof(struct ip45hdr_p3);
	char *ip6data = ip6pkt + sizeof(struct ip6_hdr);
	struct in45_addr s45addr;
	ssize_t datalen;
	uint16_t sport = 0;
	uint16_t dport = 0;
	struct session_entry_t *ses_rec;


	datalen = len45 - sizeof(struct ip45hdr_p3);

	/* get source and destination IP45 address from the packet */
	stck45_to_in45(&s45addr, &peer45_addr->sin_addr, &ip45h->s45stck, ip45h->s45mark);

	/* prepare IPv6 packet */
	memset(ip6h, 0, sizeof(struct ip6_hdr));

	ip6h->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0); /* 4 bits version, 4 bits priority */
	ip6h->ip6_plen = htons(datalen);	/* payload length */
	ip6h->ip6_nxt = ip45h->nexthdr;		/* next header */
	//ip6h->ip6_hlim = htons(ntohs(ip45h->ttl) - 1);	/*  hop limit */ 
	ip6h->ip6_hlim = 2;	/*  hop limit */ 

	/* lookup for SID */
	ses_rec = session_table_lookup_sid(&sessions, &ip45h->sid);
	if (ses_rec == NULL) {	/* the session not seen before */
		struct session_entry_t tmp;

		memcpy(&tmp.init_s45addr, &s45addr, sizeof(struct in45_addr));
		/* some system do not accept ::a.b.c.d address so we have to help wit that */
		/* converting address to 255.a.b.c.d */
	
		if (ip45h->s45mark == 0) {
			((char *)&tmp.init_s45addr)[11] = 0xFF;
		}
	
		tmp.proto = ip45h->nexthdr;
		tmp.sid.s45_sid64[0] = ip45h->sid.s45_sid64[0];
		tmp.sid.s45_sid64[1] = ip45h->sid.s45_sid64[1];
		tmp.last_45port = ntohs(peer45_addr->sin_port);
		ses_rec = session_table_add(&sessions, &tmp);
		DEBUG("New remote session sid: %016lx:%016lx\n", 
					(unsigned long)ip45h->sid.s45_sid64[0], 
					(unsigned long)ip45h->sid.s45_sid64[1]);
	}

	memcpy(&ses_rec->last_s45addr, &s45addr, sizeof(struct in45_addr));
	ses_rec->last_45port = ntohs(peer45_addr->sin_port);
	//ses_rec->last_45port = ntohs(ip45h->ip45sp);
/*	memcpy(&ses_rec->last_d45addr, &ip45h->d45addr, sizeof(ip45h->s45addr)); */

	/* src, dst address */
	memcpy(&ip6h->ip6_src, &ses_rec->init_s45addr, sizeof(ip6h->ip6_src)); 
	memcpy(&ip6h->ip6_dst, &local_addr, sizeof(ip6h->ip6_dst));
//	inet_pton(AF_INET6, "2001:17c:1220:f565::93e5:f0f7", &ip6h->ip6_dst);

	/* copy data to the new buffer */
	memcpy(ip6data, ip45data, len45 - sizeof(struct ip45hdr_p3));

	/* update checksum */
	switch (ip6h->ip6_nxt) {
		case IPPROTO_TCP: {

			struct tcphdr *tcp = (struct tcphdr*)ip6data;
			char xbuf[PKT_BUF_SIZE];
			int xptr = 0;
			uint32_t ip6nxt = htonl(ip6h->ip6_nxt);
			uint32_t tcp_len = htonl(datalen);
			

			/* an ugly way to cumpute TCP checksum - to be repaired */
			tcp->th_sum = 0x0;
			memcpy(xbuf + xptr, (char *)&(ip6h->ip6_src), sizeof(struct in6_addr));
			xptr += sizeof(ip6h->ip6_src);
			memcpy(xbuf + xptr, &ip6h->ip6_dst, sizeof(ip6h->ip6_dst));
			xptr += sizeof(ip6h->ip6_dst);
			memcpy(xbuf + xptr, &tcp_len, sizeof(uint32_t));
			xptr += sizeof(uint32_t);
			memcpy(xbuf + xptr, &ip6nxt, sizeof(ip6nxt));
			xptr += sizeof(ip6nxt);
			memcpy(xbuf + xptr, ip6data, datalen);
			xptr += datalen;
			tcp->th_sum = inet_cksum(xbuf, xptr);

			sport = tcp->th_sport;
			dport = tcp->th_dport;

		} break;
		case IPPROTO_UDP: {
			struct udphdr *udp = (struct udphdr*)ip6data;
			udp->uh_sum = 0x0;
			sport = udp->uh_sport;
			dport = udp->uh_dport;
		} break;
				
	}

	ses_rec->sport = sport;
	ses_rec->dport = dport;

	return datalen + sizeof(struct ip6_hdr);
}

/* process IPv6 packet and prepare it as IP45 packet*/
/* !1 - we expect that ipv6 buffer is big enough to handle data */
ssize_t ipv6_to_ip45(char *ip6pkt, ssize_t len6, char *ip45pkt, struct sockaddr_in *peer45_addr) {
	struct ip45hdr_p3 *ip45h = (struct ip45hdr_p3 *)ip45pkt;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)ip6pkt;
	char *ip45data = ip45pkt + sizeof(struct ip45hdr_p3);
	char *ip6data = ip6pkt + sizeof(struct ip6_hdr);
	ssize_t datalen;
	uint16_t sport = 0;
	uint16_t dport = 0;
	struct session_entry_t *ses_rec;
//	uint16_t sid_hash = 0;


	if (len6 - sizeof(struct ip6_hdr) != ntohs(ip6h->ip6_plen)) {
		DEBUG("Invalid IPv6 packet size \n");
		return -1;
	}
	datalen = len6 - sizeof(struct ip6_hdr);

	/* source address have to be loopback */
	if( ! memcmp(&ip6h->ip6_src, &local_addr, sizeof(ip6h->ip6_src)) == 0 ) {
	//	DEBUG("Not valid src \n");
		return 0; /* silent error */
	}

	/* update checksum */
	switch (ip6h->ip6_nxt) {
		case IPPROTO_TCP: {
			struct tcphdr *tcp = (struct tcphdr*)ip6data;

			tcp->th_sum = 0x0;

			sport = tcp->th_sport;
			dport = tcp->th_dport;

		} break;
		case IPPROTO_UDP: {
			struct udphdr *udp = (struct udphdr*)ip6data;

			udp->uh_sum = 0x0;

			sport = udp->uh_sport;
			dport = udp->uh_dport;
		} break;
				
	}

	/* lookup for record in session table */
	/* all srcs and dsts are switched (opposite direction) */
	ses_rec = session_table_lookup(&sessions, dport, sport, ip6h->ip6_nxt);
	if (ses_rec == NULL) {	/* the session not seen before */
		struct session_entry_t tmp;
		memcpy(&tmp.init_s45addr, &ip6h->ip6_dst, sizeof(ip6h->ip6_dst));
		memcpy(&tmp.last_s45addr, &ip6h->ip6_dst, sizeof(ip6h->ip6_dst));
/*		memcpy(&tmp.init_d45addr, &ip6h->ip6_src, sizeof(ip6h->ip6_src)); */
		tmp.proto = ip6h->ip6_nxt;
		tmp.sport = dport;
		tmp.dport = sport;
		//tmp.sid.s45_sid32[0] = 10;
		mksid(&tmp.sid);
		tmp.last_45port = IP45_COMPAT_UDP_PORT;
		ses_rec = session_table_add(&sessions, &tmp);
		DEBUG("new sid %08x.%08x.%08x.%08x created\n", 
				(unsigned int)ntohl((unsigned int)tmp.sid.s45_sid32[0]), 
				(unsigned int)ntohl((unsigned int)tmp.sid.s45_sid32[1]), 
				(unsigned int)ntohl((unsigned int)tmp.sid.s45_sid32[2]), 
				(unsigned int)ntohl((unsigned int)tmp.sid.s45_sid32[3]));
	}

	/* create IP45 header */
	memset(ip45h, 0x0, sizeof(struct ip45hdr_p3));


	ip45h->nexthdr = ip6h->ip6_nxt;		/* next header */
	ip45h->sid.s45_sid64[0] = ses_rec->sid.s45_sid64[0];
	ip45h->sid.s45_sid64[1] = ses_rec->sid.s45_sid64[1];
	peer45_addr->sin_family = AF_INET;
	peer45_addr->sin_port = htons(ses_rec->last_45port);

	/* create dst IPv4 IP45stck address and d45mark  */
	ip45h->d45mark = in45_to_stck45(&(peer45_addr->sin_addr), 
						&ip45h->d45stck, 
						(void *)&ses_rec->last_s45addr);

	/* copy data to the new buffer */
	memcpy(ip45data, ip6data, datalen);

	return datalen + sizeof(struct ip45hdr_p3);
}

/* build the ICMPv6 packets (IPv6 + ICMPv6 part) */
/* the buffer have to contain enough space to   */
/* build the requested packet including the body part */
int build_icmp6_pkt(char *pkt, unsigned char type, unsigned char code, char *body, int body_len) {

    struct ip6_hdr *ip6h = (void *)pkt;
    struct icmp6_hdr *icmp6h = (void *)pkt + sizeof(struct ip6_hdr);

	ip6h->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0); 
	ip6h->ip6_plen = htons(sizeof(struct ip6_hdr) + body_len);
	ip6h->ip6_nxt = IPPROTO_ICMPV6;
	icmp6h->icmp6_type = type;
	icmp6h->icmp6_code = code;
	icmp6h->icmp6_code = code;

	if (body != NULL && body_len > 0) {
		memcpy(&icmp6h->icmp6_dataun, body, body_len);
	}
	

    {
    uint32_t ip6nxt = htonl(ip6h->ip6_nxt);
    uint32_t icmp_len = htonl(sizeof(struct ip6_hdr) + body_len);
    char xbuf[PKT_BUF_SIZE];
    int xptr = 0;

    /* an ugly way to cumpute TCP checksum - to be repaired */
    icmp6h->icmp6_cksum = 0x0;
    memcpy(xbuf + xptr, (char *)&(ip6h->ip6_src), sizeof(struct in6_addr));
    xptr += sizeof(ip6h->ip6_src);
    memcpy(xbuf + xptr, &ip6h->ip6_dst, sizeof(ip6h->ip6_dst));
    xptr += sizeof(ip6h->ip6_dst);
    memcpy(xbuf + xptr, &icmp_len, sizeof(uint32_t));
    xptr += sizeof(uint32_t);
    memcpy(xbuf + xptr, &ip6nxt, sizeof(ip6nxt));
    xptr += sizeof(ip6nxt);
    memcpy(xbuf + xptr, icmp6h, ntohl(icmp_len));


    xptr += ntohl(icmp_len);
    icmp6h->icmp6_cksum = inet_cksum(xbuf, xptr);

    }

    return sizeof(struct ip6_hdr) + body_len;
}






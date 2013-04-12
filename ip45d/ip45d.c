#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <pthread.h>
#include "ip45.h"
#include "inet_ntop45.h"

#define PKT_BUF_SIZE 1600
#define VERSION "$LastChangedRevision$"

#define LOG(fmt, ...) printf(fmt, ##__VA_ARGS__);
#define DEBUG(fmt, ...) printf(fmt, ##__VA_ARGS__);



int rcv45_sock, snd45_sock, snd6_sock;
int debug = 0;						/* 1 = debug mode */
pcap_t *pcap_dev;					/* pcap device */
uint64_t sid_hash_table[65536] = { };
uint32_t saddr_hash_table[65536] = { };

void usage(void) {
	printf("Multicast replicator version %s\n", VERSION);
	printf("Usage:\n");
	printf("mcrep -i <input_interface> -o <output_interface> [ -p ]  [ -s ] [ -t <ttl> ] <group> [ <group> [ ... ] ]\n");
	printf(" -t : chage default ttl (defalt: 0 = incomming ttl - 1\n");
	printf(" -p : generate PIM HELLO message on output interface \n");
	printf(" -s : change source address to output interface adress \n\n");
	exit(1);
}

uint16_t inet_cksum(addr, len) 
char *addr; 
u_int len;
{
    register int nleft = (int)len;
    register u_int16_t *w = (u_int16_t *)addr;
    u_int16_t answer = 0;
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

/* initialize bpf and prepare it for use */
int init_pcap(char *input_if_name) {
	char *pcap_expr = NULL;
	char ebuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;

	if ((pcap_dev = pcap_open_live(input_if_name, PKT_BUF_SIZE, 0, 100, ebuf)) == NULL) {
		LOG("PCAP: %s\n", ebuf);
		return 0;
	}

	/* create pcap expression */

	pcap_expr = malloc(512 + 20);
	strcpy(pcap_expr, "ip6 and src host ::1");

	DEBUG("Pcap expr: '%s'\n", pcap_expr);
	
	if (pcap_compile(pcap_dev, &fcode,  pcap_expr, 1, 0) < 0) {
		fprintf(stderr, "PCAP: %s\n", pcap_geterr(pcap_dev));
		return 0;
	}

	if (pcap_setfilter(pcap_dev, &fcode) < 0) {
		fprintf(stderr, "PCAP: %s\n", pcap_geterr(pcap_dev));
		return 0;
	}
	return 1;
}

/* initialize output socket */
int init_snd_sock() {

	u_int yes = 1;

	if ((snd45_sock=socket(AF_INET,SOCK_RAW,IPPROTO_IP45)) < 0) {   
		perror("snd_sock socket");
		return 0;
	}

	if (setsockopt(snd45_sock, IPPROTO_IP, IP_HDRINCL,(char *)&yes, sizeof(yes)) < 0 ) {
		perror("setsockopt IP_HDRINCL");
		return 0;	
	}

	return 1;
}

/* loop  receive and process IP45 packets */
void *recv45_loop(void *t) {

	int rcv45_sock;
	char buf[PKT_BUF_SIZE];
	char buf6[PKT_BUF_SIZE];
	struct ip45hdr *ip45h;
	struct ip6_hdr *ip6h;
	char *data;
	char saddr[IP45_ADDR_LEN];
	char daddr[IP45_ADDR_LEN];
	ssize_t len;
	size_t datalen;
	struct sockaddr_in6 dst_addr;
	uint16_t sid_hash = 0;		/* hash - the key to teh sid hash table */
	uint16_t sport = 0;
	uint16_t dport = 0;

	u_int yes = 1;

	if ((rcv45_sock=socket(AF_INET, SOCK_RAW, IPPROTO_IP45)) < 0) {   
		perror("rcv45_sock socket");
		exit(1);
	}

	if (setsockopt(rcv45_sock, IPPROTO_IP, IP_HDRINCL,(char *)&yes, sizeof(yes)) < 0 ) {
		perror("setsockopt IP_HDRINCL (rcv45_sock)");
		exit(1);	
	}

	if ((snd6_sock=socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {   
		perror("snd6_sock socket");
		exit(1);
	}


	if (setsockopt(snd6_sock, IPPROTO_IPV6, IP_HDRINCL,(char *)&yes, sizeof(yes)) < 0 ) {
		perror("setsockopt IP_HDRINCL (snd6_sock)");
		exit(1);	
	}

	while ( (len = recv(rcv45_sock, buf, sizeof(buf), 0)) != 0 ) {

		ip45h = (struct ip45hdr*)buf;

		if (ip45h->mver != 4 || ip45h->sver != 5 || ip45h->protocol != IPPROTO_IP45) {
			LOG("IP45: invalid IP45 packet\n");
			continue;
		}

		/* check received len */
		if (len != ntohs(ip45h->tot_len)) {
			LOG("IP45: invalid IP45 packet length (received=%u, expeted=%d)\n", 
				(unsigned int)len, ntohs(ip45h->tot_len));
			continue;
		}

		/* valid IP45 packet */
		inet_ntop45((char *)&ip45h->s45addr, saddr, IP45_ADDR_LEN);
		inet_ntop45((char *)&ip45h->d45addr, daddr, IP45_ADDR_LEN);
		
		DEBUG("Received IP45 packet %s->%s, sid=%016lx, proto=%d\n", 
			saddr, daddr, 
			(unsigned long)ip45h->sid, ip45h->nexthdr);


		/* prepare IPv6 packet */
		memset(buf6, 0, sizeof(buf6));
		ip6h = (struct ip6_hdr *)buf6;
		data = buf + sizeof(struct ip45hdr);
		datalen = len - sizeof(struct ip45hdr);
		
//		ip6h->ip6_vfc = htons(0x60); /* 4 bits version, 4 bits priority */
		ip6h->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0); /* 4 bits version, 4 bits priority */
		ip6h->ip6_plen = htons(datalen);	/* payload length */
		ip6h->ip6_nxt = ip45h->nexthdr;		/* next header */
		ip6h->ip6_hlim = htons(ntohs(ip45h->ttl) - 1);	/*  hop limit */ 
		memcpy(&ip6h->ip6_src, &ip45h->s45addr, sizeof(ip6h->ip6_src)); 
		ip6h->ip6_dst.s6_addr[15] = 1;

		/* prepare dst addr */
		memset(&dst_addr, 0, sizeof(dst_addr));
		dst_addr.sin6_family = AF_INET6;
		memcpy(&dst_addr.sin6_addr, &ip6h->ip6_dst, sizeof(dst_addr.sin6_addr));
		dst_addr.sin6_port = htons(0);

		/* update checksum */
		switch (ip6h->ip6_nxt) {
			case IPPROTO_TCP: {

				struct tcphdr *tcp = (struct tcphdr*)data;
				uint32_t ip6nxt = htonl(ip6h->ip6_nxt);
				uint32_t tcp_len = htonl(datalen);
				char xbuf[PKT_BUF_SIZE];
				int xptr = 0;

				/* an ugly way to cumpute TCP checksum - to be repaired */
				tcp->check = 0x0;
				memcpy(xbuf + xptr, &ip6h->ip6_src, sizeof(ip6h->ip6_src));
				xptr += sizeof(ip6h->ip6_src);
				memcpy(xbuf + xptr, &ip6h->ip6_dst, sizeof(ip6h->ip6_dst));
				xptr += sizeof(ip6h->ip6_dst);
				memcpy(xbuf + xptr, &tcp_len, sizeof(u_int32_t));
				xptr += sizeof(u_int32_t);
				memcpy(xbuf + xptr, &ip6nxt, sizeof(ip6nxt));
				xptr += sizeof(ip6nxt);
				memcpy(xbuf + xptr, data, datalen);
				xptr += datalen;
				tcp->check = inet_cksum(xbuf, xptr);

				sport = tcp->source;
				dport = tcp->dest;

			} break;
			case IPPROTO_UDP: {
				struct udphdr *udp = (struct udphdr*)data;
				udp->check = 0x0;
			} break;
				
		}

		/* store the sit into hash table */
		sid_hash = 0;
		sid_hash += inet_cksum(&ip45h->s45addr, sizeof(ip45h->s45addr));
		sid_hash += inet_cksum(&ip45h->nexthdr, sizeof(ip45h->nexthdr));
		sid_hash += inet_cksum(&sport, sizeof(sport));
		sid_hash += inet_cksum(&dport, sizeof(dport));
		sid_hash_table[sid_hash] = ip45h->sid;
		saddr_hash_table[sid_hash] = ip45h->daddr;
		printf("sid2 hash: %x, sid: %x\n", sid_hash, (unsigned long)ip45h->sid);
		
		/* copy data to the new buffer */
		memcpy(buf6 + sizeof(struct ip6_hdr), data, datalen);

		len = sendto(snd6_sock, buf6, datalen + sizeof(struct ip6_hdr), 0, 
					(struct sockaddr*)&dst_addr, sizeof(dst_addr) );
		if ( len <= 0) {
			perror("snd6 send");
		} else {
			inet_ntop(AF_INET6, (char *)&ip6h->ip6_src, saddr, IP45_ADDR_LEN);
			inet_ntop(AF_INET6, (char *)&ip6h->ip6_dst, daddr, IP45_ADDR_LEN);
			DEBUG("Send IPv6 packet %s -> %s, proto=%d, bytes=%d\n\n", 
				saddr, daddr,
				ip6h->ip6_nxt, (unsigned int)datalen);
		}
	}

	return NULL;
}


/* process IP6 packet and send as IP45 */
inline void recv6_loop(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {

	struct ether_header *ethh = (struct ether_header *)p;
	struct ip6_hdr *ip6h = (void *)(p + sizeof(struct ether_header));
	char buf[PKT_BUF_SIZE];
	char *data;
	//char buf6[PKT_BUF_SIZE];
	struct ip45hdr *ip45h = (struct ip45hdr *)buf;
	char saddr[IP45_ADDR_LEN];
	char daddr[IP45_ADDR_LEN];
	ssize_t len;
	struct sockaddr_in dst_addr;
	uint16_t sid_hash = 0;
	uint16_t sport = 0;
	uint16_t dport = 0;

	/* we forward only IP datagrams */
	if (ntohs(ethh->ether_type) != ETHERTYPE_IPV6) {
		return;
	}

	if (h->caplen - sizeof(struct ether_header) - sizeof(struct ip6_hdr) != ntohs(ip6h->ip6_plen)) {
		LOG("Invalid packet size \n");
		return;
	}

	inet_ntop(AF_INET6, (char *)&ip6h->ip6_src, saddr, IP45_ADDR_LEN);
	inet_ntop(AF_INET6, (char *)&ip6h->ip6_dst, daddr, IP45_ADDR_LEN);
	DEBUG("Received IPv6 packet %s -> %s, proto=%d bytes=%d\n", 
			saddr, daddr,
			ip6h->ip6_nxt, h->caplen);

	data = (char *)ip6h + sizeof(struct ip6_hdr);


	/* update checksum */
	switch (ip6h->ip6_nxt) {
		case IPPROTO_TCP: {
			struct tcphdr *tcp = (struct tcphdr*)data;

			sport = tcp->source;
			dport = tcp->dest;

		} break;
		case IPPROTO_UDP: {
			struct udphdr *udp = (struct udphdr*)data;
			udp->check = 0x0;
		} break;
				
	}

	/* find the sid into hash table  */
	sid_hash = 0;
	sid_hash += inet_cksum(&ip6h->ip6_dst, sizeof(ip6h->ip6_dst));
	sid_hash += inet_cksum(&ip6h->ip6_nxt, sizeof(ip6h->ip6_nxt));
	sid_hash += inet_cksum(&sport, sizeof(sport));
	sid_hash += inet_cksum(&dport, sizeof(dport));
	if (sid_hash_table[sid_hash] == 0) {
//		ip45h->sid = random();	/* should be random number */
		ip45h->sid = 0x0;
		ip45h->saddr = 0x0;
		printf("nosid\n");
	} else {
		ip45h->sid = sid_hash_table[sid_hash];
		ip45h->saddr = saddr_hash_table[sid_hash];
	}
	printf("sid3 hash: %x, sid: %x\n", sid_hash, (unsigned long)ip45h->sid);

	/* create IP45 header */
	memset(ip45h, 0x0, sizeof(ip45h));
	ip45h->mver = 4;
	ip45h->sver = 5;
	ip45h->protocol = IPPROTO_IP45;
	ip45h->nexthdr = ip6h->ip6_nxt;		/* next header */
	memset(&ip45h->s45addr, 0x0, sizeof(ip45h->d45addr));
	/* copy src addr to last 32bytes of src45 addr */
	memcpy((char *)&ip45h->s45addr + sizeof(ip45h->s45addr) - sizeof(ip45h->saddr), 
			(char *)&ip45h->saddr, sizeof(ip45h->saddr));
	memcpy(&ip45h->d45addr, &ip6h->ip6_dst, sizeof(ip45h->d45addr)); 
	memcpy(&ip45h->daddr, 				/* copy first non 0 32 bytes from src addr */
			ip45_addr_begin(&ip45h->d45addr), 
			sizeof(ip45h->daddr));
	ip45h->ttl = htons(ntohs(ip6h->ip6_hlim) - 1);	/*  hop limit */ 
	ip45h->tot_len = htons(ntohs(ip6h->ip6_plen) + sizeof(struct ip45hdr));
//	ip45h->check1 = inet_cksum(ip45h, sizeof(struct iphdr));
//	ip45h->check2 = inet_cksum(ip45h, sizeof(struct ip45hdr));

	/* prepare dst addr */
	memset(&dst_addr, 0x0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = ip45h->daddr;
	dst_addr.sin_port = htons(0);

	/* copy data to the new buffer */
	memcpy(buf + sizeof(struct ip45hdr), data, ntohs(ip6h->ip6_plen));

	len = sendto(snd45_sock, buf, ntohs(ip45h->tot_len), 0, 
				(struct sockaddr*)&dst_addr, sizeof(dst_addr) );
	if (len <= 0 ) {
		perror("snd45 send");
	} else {
		inet_ntop45((char *)&ip45h->s45addr, saddr, IP45_ADDR_LEN);
		inet_ntop45((char *)&ip45h->d45addr, daddr, IP45_ADDR_LEN);
		DEBUG("Send IP45 packet %s -> %s, sid=%016lx, proto=%d, bytes=%d\n\n", 
			saddr, daddr,
			(unsigned long)ip45h->sid,
			ip45h->nexthdr, (unsigned int)len);
	}
}


int main(int argc, char *argv[]) {

	pthread_t recv45_thread;
	char op;

	/* parse input parameters */
	while ((op = getopt(argc, argv, "spdi:o:t:")) != -1) {
		switch (op) {
			case '?': usage();
		}
	}

	if ( pthread_create(&recv45_thread, NULL, &recv45_loop, NULL) ) {
		perror("pthread_create recv_ip45_thread error");
		exit(2);
	}

	init_snd_sock();
	init_pcap("eth0");
	if (pcap_loop(pcap_dev, -1, &recv6_loop, NULL) < 0) { 
		LOG("PCAP: %s\n", pcap_geterr(pcap_dev));
		exit(2);
	}

	return 2;

}



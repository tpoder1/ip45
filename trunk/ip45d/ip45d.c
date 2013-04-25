
/* 
 Macros used for determing the propper platform 
 #ifdef WIN32       - Microsoft Windows 
 #ifdef __APPLE__   - MAC OS X - Darwin
 #ifdef __linux     - Linux 
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __APPLE__
#include <netinet/in.h>
#endif

#ifdef WIN32
#include <windows.h>
//#include <winsock.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <winioctl.h>
#include "tap-windows.h"
#include "ip6.h"
#else 
#include <netinet/ip6.h>
#define __FAVOR_BSD 
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#endif 

#ifdef __linux
#include <linux/if.h>
#include <linux/if_tun.h>
#define TUNDEV_NAME "/dev/net/tun"
#define TUNIF_NAME "ip45"
#endif 

#ifdef __APPLE__
#include <net/if.h>
#include "tun_ioctls.h"
#define TUNDEV_NAME "/dev/tun4"
#define TUNIF_NAME "tun4"
#endif 


#include <fcntl.h>
#include "ip45.h"
#include "inet_ntop45.h"


#define PKT_BUF_SIZE 2600
#define VERSION "$LastChangedRevision$"

#define LOG(fmt, ...) printf(fmt, ##__VA_ARGS__);
#define DEBUG(fmt, ...) printf(fmt, ##__VA_ARGS__);

struct null_hdr {
	uint32_t family;
} null_drt_t;



/* to have same structures on both linux and bsd systems */

int debug = 0;						/* 1 = debug mode */
uint64_t sid_hash_table[65536] = { };
struct in_addr source_v4_address;

void usage(void) {
	printf("Multicast replicator version %s\n", VERSION);
	printf("Usage:\n");
	printf("ip45d -4 <ip address of IPv4 interface> -6 <interface to listen IPv6 traffic>\n");
	printf(" -4 : local IPv4 address for outgoing IP45 packets\n");
	exit(1);
}

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


/* process IP45 packet and prepare it as IPv6 packet*/
/* !1 - we expect that ipv6 buffer is big enough to handle data */
ssize_t ip45_to_ipv6(char *ip45pkt, ssize_t len45, char *ip6pkt) {

	struct ip45hdr *ip45h = (struct ip45hdr *)ip45pkt;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)ip6pkt;
	char *ip45data = ip45pkt + sizeof(struct ip45hdr);
	char *ip6data = ip6pkt + sizeof(struct ip6_hdr);
	ssize_t datalen;
	uint16_t sport = 0;
	uint16_t dport = 0;
	uint16_t sid_hash = 0;


	/* check version */
	if (ip45h->mver != 4 || ip45h->sver != 5 || ip45h->protocol != IPPROTO_IP45) {
		DEBUG("IP45: invalid IP45 packet mver, sver or ptotcol\n");
		return -1;
	}

	/* check received len */
#ifdef __APPLE__
	/* some platforms have update value of tot_len in IP header */
	/* and decrases the number of byted of IP header size */	
	/* we have to ajust the value here */
	ip45h->tot_len += 20;
	ip45h->tot_len = ntohs(ip45h->tot_len);
#endif

	if ( len45 != htons(ip45h->tot_len) ) {
		DEBUG("IP45: invalid IP45 packet length\n");
		return -1;
	}
	datalen = len45 - sizeof(struct ip45hdr);

	/* prepare IPv6 packet */
	memset(ip6h, 0, sizeof(struct ip6_hdr));

//	ip6h->ip6_vfc = htons(0x60); /* 4 bits version, 4 bits priority */
	ip6h->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0); /* 4 bits version, 4 bits priority */
	ip6h->ip6_plen = htons(datalen);	/* payload length */
	ip6h->ip6_nxt = ip45h->nexthdr;		/* next header */
	ip6h->ip6_hlim = htons(ntohs(ip45h->ttl) - 1);	/*  hop limit */ 

	/* src, dst address */
	memcpy(&ip6h->ip6_src, &ip45h->s45addr, sizeof(ip6h->ip6_src)); 
	ip6h->ip6_dst.s6_addr[15] = 2;
//	inet_pton(AF_INET6, "2001:17c:1220:f565::93e5:f0f7", &ip6h->ip6_dst);

	/* copy data to the new buffer */
	memcpy(ip6data, ip45data, len45 - sizeof(struct ip45hdr));

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

	/* store the sit into hash table */
	sid_hash = 0;
	sid_hash += inet_cksum(&ip45h->s45addr, sizeof(ip45h->s45addr));
	sid_hash += inet_cksum(&ip45h->nexthdr, sizeof(ip45h->nexthdr));
	sid_hash += inet_cksum(&sport, sizeof(sport));
	sid_hash += inet_cksum(&dport, sizeof(dport));
	sid_hash_table[sid_hash] = ip45h->sid;

	return datalen + sizeof(struct ip6_hdr);
}

/* process IPv6 packet and prepare it as IP45 packet*/
/* !1 - we expect that ipv6 buffer is big enough to handle data */
ssize_t ipv6_to_ip45(char *ip6pkt, ssize_t len6, char *ip45pkt) {
	struct ip45hdr *ip45h = (struct ip45hdr *)ip45pkt;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)ip6pkt;
	char *ip45data = ip45pkt + sizeof(struct ip45hdr);
	char *ip6data = ip6pkt + sizeof(struct ip6_hdr);
	ssize_t datalen;
	uint16_t sport = 0;
	uint16_t dport = 0;
	uint16_t sid_hash = 0;
	static const unsigned char localhost_bytes[] =
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };


	if (len6 - sizeof(struct ip6_hdr) != ntohs(ip6h->ip6_plen)) {
		DEBUG("Invalid IPv6 packet size \n");
		return -1;
	}
	datalen = len6 - sizeof(struct ip6_hdr);

	/* source address have to be loopback */
	if( ! memcmp(&ip6h->ip6_src, &localhost_bytes, sizeof(ip6h->ip6_src)) == 0 ) {
		DEBUG("Not valid src \n");
		return -1;
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

	/* create IP45 header */
	memset(ip45h, 0x0, sizeof(struct ip45hdr));

	/* find the sid into hash table  */
	sid_hash = 0;
	sid_hash += inet_cksum(&ip6h->ip6_dst, sizeof(ip6h->ip6_dst));
	sid_hash += inet_cksum(&ip6h->ip6_nxt, sizeof(ip6h->ip6_nxt));
	sid_hash += inet_cksum(&sport, sizeof(sport));
	sid_hash += inet_cksum(&dport, sizeof(dport));
	if (sid_hash_table[sid_hash] == 0) {
		//ip45h->sid = random();	/* should be random number */
		ip45h->sid = rand();	/* should be random number */
		DEBUG("new sid %lx created\n", (unsigned long)ip45h->sid);
	} else {
		ip45h->sid = sid_hash_table[sid_hash];
	}

	ip45h->mver = 4;
	ip45h->sver = 5;
	ip45h->protocol = IPPROTO_IP45;
	ip45h->nexthdr = ip6h->ip6_nxt;		/* next header */
//	memset(&ip45h->s45addr, 0x0, sizeof(ip45h->d45addr));
	ip45h->saddr = (uint32_t)source_v4_address.s_addr;

	/* copy src addr to last 32bytes of src45 addr */
	memcpy((char *)&ip45h->s45addr + sizeof(ip45h->s45addr) - sizeof(ip45h->saddr), 
			(char *)&ip45h->saddr, sizeof(ip45h->saddr));
	memcpy(&ip45h->d45addr, &ip6h->ip6_dst, sizeof(ip45h->d45addr)); 
	memcpy(&ip45h->daddr, 				/* copy first non 0 32 bytes from src addr */
			ip45_addr_begin(&ip45h->d45addr), sizeof(ip45h->daddr));
	ip45h->ttl = htons(ntohs(ip6h->ip6_hlim) - 1);	/*  hop limit */ 


	ip45h->tot_len = ntohs(datalen + sizeof(struct ip45hdr));
#ifdef __APPLE__
	/* BSD requires it in host order Linux not */
	ip45h->tot_len = htons(ip45h->tot_len);
#endif
	ip45h->dmark = 12 - (ip45_addr_begin(&ip45h->d45addr) - (void *)&ip45h->d45addr);
//	ip45h->check1 = inet_cksum(ip45h, 5);
//	ip45h->check1 = inet_cksum(ip45h, sizeof(struct iphdr));
//	ip45h->check2 = inet_cksum(ip45h, sizeof(struct ip45hdr));

	/* copy data to the new buffer */
	memcpy(ip45data, ip6data, datalen);

	return datalen + sizeof(struct ip45hdr);
}


int tun_alloc(char *dev) {

	struct ifreq ifr;
	int fd, err;
	int no = 0;
	char *clonedev = TUNDEV_NAME;


	if( (fd = open(clonedev, O_RDWR)) < 0 ) {
		perror("open: ");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	if (*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

#ifdef __linux
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	/* try to create the device */
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		perror("ioctl TUNSETIFF: ");
		close(fd);
		return err;
	}
#endif 

#ifdef __APPLE__
	if (ioctl(fd, TUNSIFHEAD, &no) < 0) {
		perror("ioctl TUNSIFHEAD: ");
		return -1;
	}

	/* try to create the device */
/*
	if( (err = ioctl(fd, SIOCGIFFLAGS, (void *) &ifr)) < 0 ) {
		perror("ioctl SIOCGIFFLAGS: ");
		close(fd);
		return err;
	}
*/
#endif

	strcpy(dev, ifr.ifr_name);

	return fd;
}

/* initialize output socket */
int init_sock() {

	int sock;
	int yes = 1;

	if ((sock=socket(AF_INET,SOCK_RAW,IPPROTO_IP45)) < 0) {   
		perror("snd_sock socket");
		return -1;
	}

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL,(char *)&yes, sizeof(yes)) < 0 ) {
		perror("setsockopt IP_HDRINCL");
		return -1;	
	}

	return sock;
}

int main(int argc, char *argv[]) {

	char tun_name[IFNAMSIZ] = TUNIF_NAME;
	char buf45[PKT_BUF_SIZE];
	char buf6[PKT_BUF_SIZE];
//	struct tun_pi *tunh = (struct tun_pi *)buf6;
//	struct ether_header *ethh = (struct ether_header *)buf6;
//	struct null_hdr *nullh = (struct null_hdr *)buf6;
//	struct ip6_hdr *ip6h = (struct ip6_hdr *)(buf6 + sizeof(struct tun_pi));
//	struct ip6_hdr *ip6h = (struct ip6_hdr *)(buf6 + sizeof(struct ether_header));
//	struct ip6_hdr *ip6h = (struct ip6_hdr *)(buf6 + sizeof(struct null_hdr));
	struct ip6_hdr *ip6h = (struct ip6_hdr *)buf6;
	struct ip45hdr *ip45h = (struct ip45hdr *)buf45;
	char saddr[IP45_ADDR_LEN];
	char daddr[IP45_ADDR_LEN];
	char op;
	int tunfd, sockfd, maxfd;
	struct sockaddr_in dst_addr;
	ssize_t len;

	source_v4_address.s_addr = 0x0;

	/* parse input parameters */
	while ((op = getopt(argc, argv, "4:?")) != -1) {
		switch (op) {
			case '4': 
					if (!inet_pton(AF_INET, optarg, (void *)&source_v4_address)) {
						LOG("Invalid IPv4 address %s\n", optarg);
						exit(1);
					};
					break;
			case '?': usage();
		}
	}


	if (source_v4_address.s_addr == 0x0) {
		LOG("Source address no initalised (option -4)\n");
		exit(2);
	} else {
		char buf[200];
		inet_ntop(AF_INET, &source_v4_address, (void *)&buf, 200);
		LOG("Source IPv4 address: %s\n", buf);
	}


	if ( (tunfd = tun_alloc(tun_name)) < 0 ) {
		LOG("Cant initialize ip45 on interface\n");
		exit(2);
	}
	LOG("ip45 device: %s\n", tun_name);

	if ((sockfd = init_sock()) < 0) {
		LOG("Cant initialize ip45 socket\n");
		exit(2);
	}

	maxfd = (tunfd > sockfd) ? tunfd : sockfd;

	for (;;) { 
		int ret;
		fd_set rd_set;	

		FD_ZERO(&rd_set);
		FD_SET(tunfd, &rd_set); 
		FD_SET(sockfd, &rd_set);

		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

/*
		if (ret < 0 && errno == EINTR) {
			continue;
		}
*/

		if (ret < 0) {
			perror("select()");
			exit(2);
		}

		if ( FD_ISSET(sockfd, &rd_set) ) {
			/* IP45 received */

			if ( (len = recv(sockfd, buf45, sizeof(buf45), 0)) <= 0 ) {
				perror("recv: ");
				continue;
			}

			len = ip45_to_ipv6(buf45, len, (char *)ip6h);

			if (len <= 0 ) {
				LOG("Invalid IP45 packet\n");
				continue;
			}

			/* valid IP45 packet */
			ip45h = (struct ip45hdr *)buf45;

			inet_ntop45((char *)&ip45h->s45addr, saddr, IP45_ADDR_LEN);
			inet_ntop45((char *)&ip45h->d45addr, daddr, IP45_ADDR_LEN);
		
			DEBUG("Received IP45 packet %s->%s, sid=%016lx, proto=%d\n", 
				saddr, daddr, 
				(unsigned long)ip45h->sid, ip45h->nexthdr);

			//tunh->flags = 0x0;
			//tunh->proto = htons(ETH_P_IPV6);
		//	ethh->ether_type = htons(ETHERTYPE_IPV6);
//			ethh->ether_shost[5] = 5;
//			ethh->ether_dhost[5] = 1;
//			nullh->family = AF_INET6;

			if ( (len = write(tunfd, buf6, len) ) < 0 ) {
			//if ( (len = write(tunfd, buf6, len + sizeof(struct tun_pi))) < 0 ) {
			//if ( (len = write(tunfd, buf6, len + sizeof(struct ether_header))) < 0 ) {
			//if ( (len = pcap_inject(pcap_dev, buf6, len + sizeof(struct ether_header))) < 0 ) {
		//	if ( (len = pcap_sendpacket(pcap_dev, buf6, len + sizeof(struct ether_header))) < 0 ) {
				perror("send tunfd");
			}
		}

		if(FD_ISSET(tunfd, &rd_set)) {
			/* IPv6 received */

			if ( (len = read(tunfd, buf6, sizeof(buf6))) <= 0 ) {
				perror("read: ");
				continue;
			}

			len = ipv6_to_ip45(buf6, len, buf45);

			if (len <= 0 ) {
				LOG("Invalid IPv6 packet\n");
				continue;
			}

			inet_ntop(AF_INET6, (char *)&ip6h->ip6_src, saddr, IP45_ADDR_LEN);
			inet_ntop(AF_INET6, (char *)&ip6h->ip6_dst, daddr, IP45_ADDR_LEN);
			DEBUG("Received IPv6 packet %s -> %s, proto=%d bytes=%d\n", 
					saddr, daddr,
					ip6h->ip6_nxt, (int)len);

			/* prepare dst addr */
			memset(&dst_addr, 0x0, sizeof(dst_addr));
			dst_addr.sin_family = AF_INET;
			dst_addr.sin_addr.s_addr = ip45h->daddr;
			dst_addr.sin_port = htons(0);

			len = sendto(sockfd, buf45, len, 0, 
				(struct sockaddr*)&dst_addr, sizeof(dst_addr) );
			if ( len < 0 ) {
				perror("send sockfd");
			}
		}
	}
}



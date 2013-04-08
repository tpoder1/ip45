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
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <pthread.h>

#define PKT_BUF_SIZE 1600
#define VERSION "$LastChangedRevision$"


#ifndef IPPROTO_IP45
#define IPPROTO_IP45 155
#endif

int rcv45_sock, snd45_sock, snd6_sock;
int debug = 0;						/* 1 = debug mode */
pcap_t *pcap_dev;					/* pcap device */

void usage(void) {
	printf("Multicast replicator version %s\n", VERSION);
	printf("Usage:\n");
	printf("mcrep -i <input_interface> -o <output_interface> [ -p ]  [ -s ] [ -t <ttl> ] <group> [ <group> [ ... ] ]\n");
	printf(" -t : chage default ttl (defalt: 0 = incomming ttl - 1\n");
	printf(" -p : generate PIM HELLO message on output interface \n");
	printf(" -s : change source address to output interface adress \n\n");
	exit(1);
}

int inet_cksum(addr, len) 
u_int16_t *addr; 
u_int len;
{
    register int nleft = (int)len;
    register u_int16_t *w = addr;
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




u_short cksum(u_short *buf, int count) {
	register u_long sum = 0;
	while (count--) {
		sum += *buf++;
		if (sum & 0xFFFF0000) { 
			/* carry occurred, so wrap around */
			sum &= 0xFFFF;
			sum++;
		}
	}
	return ~(sum & 0xFFFF);
}

u_short crc16(u_char *data, int len) {
    u_short *p = (u_short *)data,
            crc = 0;
    int     size = len >> 1;

    while(size--) crc ^= *p++;
           // this ntohs(htons) is needed for big/little endian compatibility
    if(len & 1) crc ^= ntohs(htons(*p) & 0xff00);
    return(crc);
}

/* initialize bpf and prepare it for use */
int init_pcap(char *input_if_name) {
	char *pcap_expr = NULL;
	char ebuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;
	int grp_cnt = 0;

	if ((pcap_dev = pcap_open_live(input_if_name, PKT_BUF_SIZE, 0, 100, ebuf)) == NULL) {
		fprintf(stderr,"PCAP: %s\n", ebuf);
		return 0;
	}

	/* create pcap expression */

	pcap_expr = malloc(512 + 20 * grp_cnt);
	strcpy(pcap_expr, "ipv6");

	if (debug) printf("Pcap expr: '%s'\n", pcap_expr);
	
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


/*
	if_addr.s_addr = output_if_addr->s_addr;         
	if (setsockopt(snd_sock, IPPROTO_IP, IP_MULTICAST_IF, &if_addr, sizeof(if_addr)) < 0 ) {
		perror("setsockopt IP_MULTICAST_IF");
		return 0;
	}
*/

	return 1;
}

/* initialize pim output socket - loop */
void *recv45_loop(void *t) {

	int rcv45_sock;
	char buf[PKT_BUF_SIZE];
	size_t len;
	//int snd6_sock;
	u_int yes = 1;

	if ((rcv45_sock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {   
		perror("ip45_sock socket");
		exit(1);
	}

	if (setsockopt(rcv45_sock, IPPROTO_IP, IP_HDRINCL,(char *)&yes, sizeof(yes)) < 0 ) {
		perror("setsockopt IP_HDRINCL (ip45_sock)");
		exit(1);	
	}

	printf("XXX\n");

	while ( len = recv(rcv45_sock, buf, sizeof(buf), 0) ) {
		printf("Received IP45 %d\n", len);
	}
/*
	while (1) {
		if (sendto(pim_sock, (char *)&pimp, sizeof(pimp), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0 ) {
			perror("pim_sendto");
		} 
		if (debug) { printf("PIM HELLO sent from %s to %s\n", inet_ntoa(if_addr), PIM_HELLO_GROUP); }
		sleep(PIM_HELLO_INTERVAL);
	}
*/

	return NULL;
}


/* process one packet and send */
inline void process_pkt(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {

	struct ether_header *eth_pkt = (struct ether_header *)p;
	struct ippacket {
		struct ip ip;
		char data[PKT_BUF_SIZE];
	};

	struct ippacket *pkt = (void *)(p + sizeof(struct ether_header));
//	struct ip *pkt = (struct ether_header *)ipdata;
	struct sockaddr_in dst_addr;
	char src[15], dst[15];

	/* we forward only IP datagrams */
	if (ntohs(eth_pkt->ether_type) == ETHERTYPE_IP) {

//		pkt->ip.ip_src.s_addr = output_if_addr.s_addr;

		strcpy(src, inet_ntoa(pkt->ip.ip_src));
		strcpy(dst, inet_ntoa(pkt->ip.ip_dst));

		pkt->ip.ip_ttl		-= 1;		/* ttl must by set through setsockopt IP_MULTICAST_TTL */
		pkt->ip.ip_off		= htons(pkt->ip.ip_off);
		pkt->ip.ip_len		= htons(pkt->ip.ip_len);
		 
		/* ignore packets with ttl=1 */		
		if (pkt->ip.ip_ttl == 0 ) {
			return;
		}

		if (debug) fprintf(stderr, "R: %-15s -> %-15s (pktlen=%04u,ttl=%02u,proto=%02u,ident=%04u,foffset=%04u)\n", 
					src, dst, h->caplen, pkt->ip.ip_ttl, pkt->ip.ip_p, htons(pkt->ip.ip_id), htons(pkt->ip.ip_off));

		if (h->caplen - sizeof(struct ether_header) != pkt->ip.ip_len) {
			fprintf(stderr, "Packet size mismas %u - %lu != %d. R: %-15s -> %-15s (pktlen=%04u,ttl=%02u,proto=%02u,ident=%04u,foffset=%04u)\n", 
					h->caplen, sizeof(struct ether_header), pkt->ip.ip_len,
					src, dst, h->caplen, pkt->ip.ip_ttl, pkt->ip.ip_p, htons(pkt->ip.ip_id), htons(pkt->ip.ip_off));
            
		}	

/*
		if (setsockopt(snd6_sock, IPPROTO_IP, IP_MULTICAST_TTL,(char *)&(pkt->ip.ip_ttl), sizeof(pkt->ip.ip_ttl)) < 0 ) {
			perror("IP_MULTICAST_TTL");
			return;
		}
*/

		bzero(&dst_addr, sizeof(dst_addr));
		memset(&dst_addr, 0, sizeof(dst_addr));
		dst_addr.sin_family			= AF_INET;
		dst_addr.sin_addr.s_addr	= pkt->ip.ip_dst.s_addr;
		dst_addr.sin_port			= htons(0);

/*
		if (sendto(snd_sock, (char *)pkt, pkt->ip.ip_len, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0 ) {
			perror("sendto");
		}
*/
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

//	if (pcap_loop(pcap_dev, -1, &process_pkt, NULL) < 0) { 
//		fprintf(stderr, "PCAP: %s\n", pcap_geterr(pcap_dev));
//	}
//
	while (1);

	return 2;

}



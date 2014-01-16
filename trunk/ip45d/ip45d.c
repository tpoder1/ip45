

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
#include <time.h>


#ifdef __APPLE__
#include <netinet/in.h>
#endif

#ifdef WIN32
#include <windows.h>
#include <winbase.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "tap-windows.h"
#include "ether.h"
#include "ip6.h"
#include "icmp6.h"
#include "compat_win.h"
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
#define TUNIF_CMD "/sbin/ifconfig %s add %s/%d up"
#endif 

#ifdef __APPLE__
#include <net/if.h>
#include "tun_ioctls.h"
#define TUNDEV_NAME "/dev/tun4"
#define TUNIF_NAME "tun4"
#define TUNIF_CMD "/sbin/ifconfig %s inet6 %s/%d up"
#endif 

#ifdef WIN32 
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define TUNIF_NAME "ip45"
#endif

#include <fcntl.h>
#include <ip45.h>
#include "inet_ntop45.h"
#include "session_table.h"


#define PKT_BUF_SIZE 2600
#define VERSION "$LastChangedRevision$"

#define LOG(fmt, ...) printf(fmt, ##__VA_ARGS__);
#define DEBUG(fmt, ...) printf(fmt, ##__VA_ARGS__);

#define LOCAL_IPV6_ADDR "0:0:0:0:0:1:0:0"
#define LOCAL_IPV6_MASKLEN 8


unsigned char local_addr[16];

/*

struct null_hdr {
	uint32_t family;
} null_drt_t;

*/


#ifdef WIN32
/* temporary until the code will be cleaned up */
HANDLE ptr;
int sock; 

OVERLAPPED olReading, olWriting;

char virt_mac[ETH_ALEN] = { 0x00, 0x00, 0x93, 0x92, 0xD7, 0x8F };
char host_mac[ETH_ALEN] = { 0x00, 0xFF, 0x93, 0x92, 0xD7, 0x8F };
#endif

int debug = 0;						/* 1 = debug mode */
struct session_table_t sessions;

void usage(void) {
	printf("IP45 daemon version %s, package version: %s\n", VERSION, PKG_VERSION);
	printf("Usage:\n");
	printf("ip45d [ -D  ] [ -v ] \n");
	printf(" -D : daemonize process - only on POSIX (non WINDOWS) platform\n");
	printf(" -v : provide more debug information\n");
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

/* generates the random SID */
void mksid(struct in45_sid *sid) {
	int i; 

	if  ( RAND_MAX < 0xFFFF ) {
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
		mksid(&tmp.sid);
		tmp.last_45port = IP45_COMPAT_UDP_PORT;
		ses_rec = session_table_add(&sessions, &tmp);
		DEBUG("new sid %016lx:%016lx created\n", 
				(unsigned long)tmp.sid.s45_sid64[0], 
				(unsigned long)tmp.sid.s45_sid64[1]);
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


/* initialize output socket */
int init_sock() {

	int sock;
	struct sockaddr_in ls; 
#ifdef __linux
	int yes = 1;
#endif

//	if ((sock=socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) { 
#ifdef WIN32
	if (( sock = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET) {
		LOG("WSASocket failed with error: %d\n", WSAGetLastError());
		closesocket(sock);	
		return -1;
	}
#else 
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {   
		perror("sock socket");
		return -1;
	}
#endif

#ifdef __linux
	if (setsockopt(sock, IPPROTO_IP, SO_NO_CHECK,(char *)&yes, sizeof(yes)) < 0 ) {
		perror("setsockopt SO_NO_CHECK");
		return -1;	
	}
#endif

	memset(&ls, 0, sizeof(struct sockaddr_in));
	ls.sin_family = AF_INET;
	ls.sin_addr.s_addr = INADDR_ANY;
	ls.sin_port = htons(IP45_COMPAT_UDP_PORT);
	//ls.sin_port = IP45_COMPAT_UDP_PORT;
	if (bind(sock, (struct sockaddr *)&ls, sizeof(struct sockaddr_in)) < 0 ) {
#ifdef WIN32
		LOG("WSASocket failed with error: %d\n", WSAGetLastError());
		closesocket(sock);	
#else 
		perror("bind"); 
		return -1;
#endif
	}
	
	return sock;
}

/* followin code is compiled only on non windows (POSIX) systems */
#ifndef WIN32

/* POSIX only : daemonize process */
static void daemonize_posix(void) {
	pid_t pid, sid;

	/* already a daemon */
	if ( getppid() == 1 ) return;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		exit(2);
	}
	/* If we got a good PID, then we can exit the parent process. */
	if (pid > 0) {
		exit(0);
	}

	/* At this point we are executing as the child process */

	/* Change the file mode mask */
	//umask(0);
   
	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		exit(2);
	}
   

	/* Change the current working directory.  This prevents the current
	* directory from being locked; hence not being able to remove it. */
	if ((chdir("/")) < 0) {
		exit(2);
	}

	/* Redirect standard files to /dev/null */
	freopen( "/dev/null", "r", stdin);
	freopen( "/dev/null", "w", stdout);
	freopen( "/dev/null", "w", stderr);
}

/* POSIX only: alloc tun device */
int tun_alloc_posix(char *dev) {

	struct ifreq ifr;
	int fd, err, no;
	char *clonedev = TUNDEV_NAME;

	err = 0;
	no = 0;


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

/* POSIX only: main loop */
int main_loop_posix(int verbose_opt) {

	char tun_name[IFNAMSIZ] = TUNIF_NAME;
	char buf45[PKT_BUF_SIZE];
	char buf6[PKT_BUF_SIZE];
	struct ip6_hdr *ip6h = (struct ip6_hdr *)buf6;
	struct ip45hdr_p3 *ip45h = (struct ip45hdr_p3 *)buf45;
	struct in45_addr s45addr;
	char saddr[IP45_ADDR_LEN];
	char daddr[IP45_ADDR_LEN];
	int tunfd, sockfd, maxfd;
	struct sockaddr_in peer45_addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	ssize_t len;
	char cmdbuf[1024];
	int ret;

	if ( (tunfd = tun_alloc_posix(tun_name)) < 0 ) {
		LOG("ERROR Cant initialize ip45 on interface\n");
		exit(2);
	}
	LOG("ip45 device: %s\n", tun_name);
	
	// config virtual interface
	sprintf(cmdbuf, TUNIF_CMD, tun_name, LOCAL_IPV6_ADDR, LOCAL_IPV6_MASKLEN);
	LOG("Configuring interface: %s ... ", cmdbuf);
	ret = system(cmdbuf);
	if (ret < 0) {
		LOG("\nERROR Can't configure interface... exiting\n");
		exit(2);
	} else {
		LOG("OK\n");
	}
	
	

init_sock:
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

			if ( (len = recvfrom(sockfd, buf45, sizeof(buf45), 0, 
					(void *)&peer45_addr, &addrlen)) <= 0 ) {
				perror("recv: ");
				close(sockfd);
				goto init_sock;
			}

			len = ip45_to_ipv6(&peer45_addr, buf45, len, (char *)ip6h);

			if (len <= 0 ) {
				LOG("Invalid IP45 packet\n");
				continue;
			}

			/* valid IP45 packet */
			ip45h = (struct ip45hdr_p3 *)buf45;

			stck45_to_in45(&s45addr, (void *)&peer45_addr.sin_addr, &ip45h->s45stck, ip45h->s45mark);

			if (verbose_opt) {
				inet_ntop45((char *)&s45addr, saddr, IP45_ADDR_LEN);
		
				DEBUG("Received IP45 packet %s->{me}, sid=%016lx:%016lx, proto=%d\n", 
					saddr,  
					(unsigned long)ip45h->sid.s45_sid64[0], 
					(unsigned long)ip45h->sid.s45_sid64[1], 
					ip45h->nexthdr);
			}


			if ( (len = write(tunfd, buf6, len) ) < 0 ) {
				perror("send tunfd");
			}
		}

		if(FD_ISSET(tunfd, &rd_set)) {
			/* IPv6 received */

			if ( (len = read(tunfd, buf6, sizeof(buf6))) <= 0 ) {
				perror("read: ");
				continue;
			}

			len = ipv6_to_ip45(buf6, len, buf45, &peer45_addr);

			if (len <= 0) {
				if (len < 0) {
					LOG("Invalid IPv6 packet\n");
				}
				continue;
			}


			if (verbose_opt) {
				inet_ntop(AF_INET6, (char *)&ip6h->ip6_src, saddr, IP45_ADDR_LEN);
				inet_ntop(AF_INET6, (char *)&ip6h->ip6_dst, daddr, IP45_ADDR_LEN);
				DEBUG("Received IPv6 packet %s -> %s, proto=%d bytes=%d\n", 
						saddr, daddr,
						ip6h->ip6_nxt, (int)len);
			}


			len = sendto(sockfd, buf45, len, 0, 
				(struct sockaddr*)&peer45_addr, sizeof(struct sockaddr_in) );
			if ( len < 0 ) {
				perror("send sockfd");
			}
		}
	}
}
#endif


/* windows specific code */
#ifdef WIN32

void GetDeviceGuid(char* szDeviceGuid) {	
	HKEY hKey = NULL;
	//if (ERROR_SUCCESS==RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}", 0, KEY_READ, &hKey))
	if (ERROR_SUCCESS==RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &hKey))
	{
		TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
		DWORD    cbName;                   // size of name string 
		TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
		DWORD    cchClassName = MAX_PATH;  // size of class string 
		DWORD    cSubKeys=0;               // number of subkeys 
		DWORD    cbMaxSubKey;              // longest subkey size 
		DWORD    cchMaxClass;              // longest class string 
		DWORD    cValues;              // number of values for key 
		DWORD    cchMaxValue;          // longest value name 
		DWORD    cbMaxValueData;       // longest value data 
		DWORD    cbSecurityDescriptor; // size of security descriptor 
		FILETIME ftLastWriteTime;      // last write time 

		DWORD i, retCode; 

		//TCHAR  achValue[MAX_VALUE_NAME]; 
		//DWORD cchValue = MAX_VALUE_NAME; 
	
		retCode = RegQueryInfoKey(
			hKey,                    // key handle 
			achClass,                // buffer for class name 
			&cchClassName,           // size of class string 
			NULL,                    // reserved 
			&cSubKeys,               // number of subkeys 
			&cbMaxSubKey,            // longest subkey size 
			&cchMaxClass,            // longest class string 
			&cValues,                // number of values for this key 
			&cchMaxValue,            // longest value name 
			&cbMaxValueData,         // longest value data 
			&cbSecurityDescriptor,   // security descriptor 
			&ftLastWriteTime);       // last write time 

		for (i=0; i<cSubKeys; i++) 
        { 
            cbName = MAX_KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i,
                     achKey, 
                     &cbName, 
                     NULL, 
                     NULL, 
                     NULL, 
                     &ftLastWriteTime); 
            if (retCode == ERROR_SUCCESS) 
            {    
				HKEY hSubKey = NULL;
				if (ERROR_SUCCESS==RegOpenKeyEx(hKey, achKey, 0, KEY_READ, &hSubKey))
				{
					BYTE szComponent[1000];
					DWORD cbData = 1000;
					DWORD dwType = REG_SZ;

					memset(szComponent, 0, 1000);
					RegQueryValueEx(hSubKey, "ComponentId", NULL, &dwType, szComponent, (void *)&cbData);
					//DEBUG("Found interface: %s\n", szComponent);
					//if (!strcmp((char *)szComponent, "tap0801"))
					if (!strcmp((char *)szComponent, "tap0901"))
					{
						cbData = 1000;
						dwType = REG_SZ;
						RegQueryValueEx(hSubKey, "NetCfgInstanceId", NULL, &dwType, (void *)szDeviceGuid, (void *)&cbData);
						break;
					}
					RegCloseKey(hSubKey);
				}
            }
        }
		RegCloseKey(hKey);
	}

}

void GetHumanName(char* szDeviceGuid, char* szHumanName)
{
	HKEY hKey = NULL;
	char szKeyName[1999];
	strcpy(szKeyName, NETWORK_CONNECTIONS_KEY);
	strcat(szKeyName, "\\");
//	strcpy(szKeyName, "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\");
	if (strlen(szDeviceGuid) > 0)
	{
		strcat(szKeyName, szDeviceGuid);
		strcat(szKeyName, "\\Connection");
		DEBUG("KEY: %s\n", szKeyName);
		if (ERROR_SUCCESS==RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0, KEY_READ, &hKey))
		{			
			DWORD cbData = 1000;
			DWORD dwType = REG_SZ;

			memset(szHumanName, 0, 1000);
			RegQueryValueEx(hKey, "Name", NULL, &dwType, (void *)szHumanName, (void *)&cbData);

			RegCloseKey(hKey);
		}
	}
}

int TAP_CONTROL_CODE(int request, int method)
{
	return CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS);
}


/* WINDOWS only: read Neighbor Solicitation message and prepare 
 * a packet with Neighbor Advertisement */
int build_nd_adv_pkt(char *virt_mac, char *buf_sol, int len, char *buf_adv) {

	struct ethhdr *eth_sol = (void *)buf_sol;
	struct ethhdr *eth_adv = (void *)buf_adv;
	struct ip6_hdr *ip6h_sol = (void *)buf_sol + sizeof(struct ethhdr);
	struct ip6_hdr *ip6h_adv = (void *)buf_adv + sizeof(struct ethhdr);
	struct nd_neighbor_solicit *icmp6h_sol = (void *)ip6h_sol + sizeof(struct ip6_hdr);
	struct nd_neighbor_advert *icmp6h_adv = (void *)ip6h_adv + sizeof(struct ip6_hdr);
	char *nd_mac_opts = (void *)icmp6h_adv + sizeof(struct nd_neighbor_advert);


	if (ip6h_sol->ip6_nxt != IPPROTO_ICMPV6) {
		return 0;
	}

	if (icmp6h_sol->nd_ns_type != ND_NEIGHBOR_SOLICIT) {
		return 0;
	}

	/* copy original packet into new one */
	memcpy(buf_adv, buf_sol, len);

	icmp6h_adv->nd_na_type = ND_NEIGHBOR_ADVERT;

	/* copy source address from the orriginal packet to the destination */
	memcpy(&ip6h_adv->ip6_dst, &ip6h_sol->ip6_src, sizeof(struct in6_addr));
	/* requested target */
	memcpy(&ip6h_adv->ip6_src, &icmp6h_sol->nd_ns_target, sizeof(struct in6_addr));

	/* set sollicited and override flag */
	icmp6h_adv->nd_na_flags_reserved = htonl(ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE);

	/* set MAC address */
	/* 0 - address type, 1 - addr length, 2 - 7 address */
	nd_mac_opts[0] = ND_OPT_TARGET_LINKADDR; /* 0x1 - source link address, 0x2 - target link address */
	memcpy(nd_mac_opts + 2, virt_mac, ETH_ALEN);


	{
	uint32_t ip6nxt = htonl(ip6h_adv->ip6_nxt);
	uint32_t icmp_len = htonl(len - sizeof(struct ip6_hdr) - sizeof(struct ethhdr));
	char xbuf[PKT_BUF_SIZE];
	int xptr = 0; 
	
	/* an ugly way to cumpute TCP checksum - to be repaired */
	icmp6h_adv->nd_na_cksum = 0x0;
	memcpy(xbuf + xptr, (char *)&(ip6h_adv->ip6_src), sizeof(struct in6_addr));
	xptr += sizeof(ip6h_adv->ip6_src);
	memcpy(xbuf + xptr, &ip6h_adv->ip6_dst, sizeof(ip6h_adv->ip6_dst));
	xptr += sizeof(ip6h_adv->ip6_dst);
	memcpy(xbuf + xptr, &icmp_len, sizeof(uint32_t));
	xptr += sizeof(uint32_t);
	memcpy(xbuf + xptr, &ip6nxt, sizeof(ip6nxt));
	xptr += sizeof(ip6nxt);
	memcpy(xbuf + xptr, icmp6h_adv, ntohl(icmp_len));
	xptr += ntohl(icmp_len);
	icmp6h_adv->nd_na_cksum = inet_cksum(xbuf, xptr);

	}

	/* fill ethernet header */
	eth_adv->h_proto = htons(ETH_P_IPV6);
	memcpy(eth_adv->h_dest, eth_sol->h_source, ETH_ALEN);
	memcpy(eth_adv->h_source, virt_mac, ETH_ALEN);
	return len;
}

/* WINDOWS only: reads data from tap and sends via socket (IPv6 -> IP45) */
DWORD WINAPI tun_to_sock_loop(  LPVOID lpParam ) {

	//HANDLE ptr;
	//int sock; 

	char rcv_ebuf6[PKT_BUF_SIZE];
	struct ethhdr *rcv_eth6 = (struct ethhdr *)rcv_ebuf6;
	char *rcv_buf6 = rcv_ebuf6 + sizeof(struct ethhdr);
	struct ip6_hdr *rcv_ip6h = (struct ip6_hdr *)rcv_buf6;

	char snd_buf45[PKT_BUF_SIZE];
//	struct ip45hdr_p3 *snd_ip45h = (struct ip45hdr_p3 *)snd_buf45;


	char saddr[IP45_ADDR_LEN];
	char daddr[IP45_ADDR_LEN];

	
//	struct in45_addr s45addr;
	struct sockaddr_in peer45_addr;
//	int client_len = sizeof(struct sockaddr);
	WSABUF SndBuf;
	DWORD Flags;

	while(1) {
//		DWORD sock_len;
		DWORD tun_len;
		DWORD snd_len;
//		DWORD dwEvent;
//		int addrlen;
//		WSANETWORKEVENTS myNetEvents;
		int rc;
		//DWORD write_len;


		ReadFile(ptr, rcv_ebuf6, PKT_BUF_SIZE, NULL, &olReading);

		WaitForSingleObject(olReading.hEvent, INFINITE);

		if (!GetOverlappedResult(ptr, &olReading, &tun_len, FALSE) || tun_len <= 0) {
			LOG("Cannot read data GetOverlappedResult\n");
			continue;
		}


		if (ntohs(rcv_eth6->h_proto) != ETH_P_IPV6) {
			continue;
		}

		/* check NS packets and inject the response */
		if (rcv_ip6h->ip6_nxt == IPPROTO_ICMPV6) {
			struct icmp6_hdr *icmp6h = (void *)rcv_ip6h + sizeof(struct ip6_hdr);
			char buf_adv[PKT_BUF_SIZE];

			if (icmp6h->icmp6_type == ND_NEIGHBOR_SOLICIT)  {
				snd_len = build_nd_adv_pkt(virt_mac, rcv_ebuf6, tun_len, buf_adv);
				LOG("ICMP solic v6 %d\n", (int)snd_len);

				/* inject ICMPv6 packet with response */
	     			if (!WriteFile(ptr, buf_adv, snd_len, NULL, &olWriting)) {
					LOG("Cannot write ICMPv6 data.  Error: %d \n", (int)GetLastError());
					exit(2);
				}
				continue;
			}
		}

		tun_len -= sizeof(struct ethhdr);
		snd_len = ipv6_to_ip45(rcv_buf6, tun_len, snd_buf45, &peer45_addr);

		if ((int)snd_len <= 0 ) {
			if ((int)snd_len < 0) {
				LOG("Invalid IPv6 packet\n");
			}
			continue;
		}

//		if (verbose_opt) {
			inet_ntop(AF_INET6, (char *)&rcv_ip6h->ip6_src, saddr, IP45_ADDR_LEN);
			inet_ntop(AF_INET6, (char *)&rcv_ip6h->ip6_dst, daddr, IP45_ADDR_LEN);
			DEBUG("Received IPv6 packet %s -> %s, proto=%d bytes=%d\n",
					saddr, daddr, rcv_ip6h->ip6_nxt, (int)tun_len);
//		}

		SndBuf.len = snd_len;
		SndBuf.buf = snd_buf45;
		Flags = 0;

		rc = WSASendTo(sock, &SndBuf, 1, &snd_len, Flags, 
			(struct sockaddr*)&peer45_addr, sizeof(struct sockaddr_in),
			NULL, NULL );

		if (rc == SOCKET_ERROR) {
			LOG("WSASendTo failed with error: %d\n",  (int)GetLastError());
		}
	} /* while */

}

/* WINDOWS only: reads data from socket and sends to tap (IP45 -> IPv6) */
DWORD WINAPI sock_to_tun_loop(  LPVOID lpParam ) {

	//HANDLE ptr;
	//int sock; 

	char snd_ebuf6[PKT_BUF_SIZE];
	struct ethhdr *snd_eth6 = (struct ethhdr *)snd_ebuf6;
	char *snd_buf6 = snd_ebuf6 + sizeof(struct ethhdr);
	struct ip6_hdr *snd_ip6h = (struct ip6_hdr *)snd_buf6;

	char rcv_buf45[PKT_BUF_SIZE];
	struct ip45hdr_p3 *rcv_ip45h = (struct ip45hdr_p3 *)rcv_buf45;

	char saddr[IP45_ADDR_LEN];
//	char daddr[IP45_ADDR_LEN];

//	char virt_mac[ETH_ALEN] = { 0x00, 0x00, 0x93, 0x92, 0xD7, 0x8F };
//	char host_mac[ETH_ALEN] = { 0x00, 0xFF, 0x93, 0x92, 0xD7, 0x8F };
	
	struct in45_addr s45addr;
	struct sockaddr_in peer45_addr;
	int client_len = sizeof(struct sockaddr);
//	int x = 0;

//	DWORD Flags;

	while(1) {
		DWORD sock_len;
//		DWORD tun_len;
		DWORD snd_len;
// write_len;
//		DWORD dwEvent;
//		int addrlen;
//		WSANETWORKEVENTS myNetEvents;
//		int rc, err;

		sock_len = recvfrom(sock, (void *)rcv_buf45, PKT_BUF_SIZE, 0, (struct sockaddr *)&peer45_addr, &client_len);
/*		if (WSAEnumNetworkEvents(sock, sockEvent, &myNetEvents)) {
			LOG("ERROR: WSAEnumNetworkEvents\n");
			exit(2);
		}
		*/

		if ( (int)sock_len < sizeof(struct ip45hdr_p3) ) {
			LOG("Received too short IP45 packet\n");
			continue;
		}

		snd_len = ip45_to_ipv6(&peer45_addr, rcv_buf45, sock_len, (char *)snd_ip6h);

		if (snd_len < 0 || snd_len == 0) {
			if (snd_len < 0) {
				LOG("Invalid IP45 packet\n");
			}
			continue;
		}

		/* valid IP45 packet */
		rcv_ip45h = (struct ip45hdr_p3 *)rcv_buf45;

		stck45_to_in45(&s45addr, (void *)&peer45_addr.sin_addr, &rcv_ip45h->s45stck, rcv_ip45h->s45mark);

//		if (verbose_opt) {
			inet_ntop45((char *)&s45addr, saddr, IP45_ADDR_LEN);
			DEBUG("Received IP45 packet %s->{me}, sid=%016lx:%016lx, proto=%d, bytes=%d\n",
				saddr,  
				(unsigned long)rcv_ip45h->sid.s45_sid64[0], 
				(unsigned long)rcv_ip45h->sid.s45_sid64[1], 
				rcv_ip45h->nexthdr, (int)sock_len);
//		}

		snd_eth6->h_proto = htons(ETH_P_IPV6);
		memcpy(snd_eth6->h_dest, host_mac, ETH_ALEN);
		memcpy(snd_eth6->h_source, virt_mac, ETH_ALEN);
		snd_len += sizeof(struct ethhdr);

	     	if (!WriteFile(ptr, snd_ebuf6, snd_len, NULL, &olWriting)) {
			LOG("Cannot write data to ip45/tun interface. Error: %d \n", (int)GetLastError());
			exit(2);
		}
	} /* while */

	return 0;
}


/* WINDOWS only: main loop */
int main_loop_win(int verbose_opt) {
//	int ptun[3] = {0x0100030a, 0x0000030a, 0x00ffffff};

	DWORD pstatus;
	DWORD pstatus_len;


	char devGuid[1000];
	char devHuman[1000];
	char fileName[1000];

//	WSABUF RcvBuf, SndBuf;
//	DWORD Flags;

	HANDLE Thread1 = 0;
//	HANDLE Thread2 = 0;

	/* prepare filehandle - TUN device */
	memset(devGuid, 0, 1000);
	GetDeviceGuid(devGuid);
	LOG("Devie GUID: %s\n", devGuid);

	GetHumanName(devGuid, devHuman);
	LOG("Humman name: %s\n", devHuman);
	sprintf(fileName, "%s%s%s", USERMODEDEVICEDIR, devGuid, TAP_WIN_SUFFIX);

	LOG("File Name: %s\n", fileName);


//	ptr = CreateFile(fileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, 
//						OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);

	ptr = CreateFile(fileName, GENERIC_READ | GENERIC_WRITE, 0, 0, 
						OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,  0);

	pstatus = 1;	
	DeviceIoControl(ptr, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &pstatus, 4, &pstatus, 4, &pstatus_len, NULL);
	/* set device to TUN mode (without Ethernet frame) */
//	DeviceIoControl(ptr, TAP_WIN_IOCTL_CONFIG_TUN, ptun, 12, ptun, 12, &len, NULL);

	olReading.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	olWriting.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	
	if ((sock = init_sock()) < 0) {
		LOG("Cant initialize ip45 socket\n");
		exit(2);
	}


	//Thread1 = CreateThread( NULL, 0, sock_to_tun_loop, NULL, 0, NULL);  
	
	Thread1 = CreateThread( NULL, 0, tun_to_sock_loop, NULL, 0, NULL);  
	if ( Thread1 == NULL) {
		LOG("Cannot create thread\n");
	}
	
//	tun_to_sock_loop(NULL);
	
	sock_to_tun_loop(NULL);
	while (1) {
	}
	
	

	return 0;
}
#endif /* #ifdef WIN32 */


int main(int argc, char *argv[]) {

	char op;
#ifndef WIN32
	int daemon_opt = 0;
#endif
	int verbose_opt = 0;


#ifdef WIN32
	WSADATA wsaData; 

	/* initialise and prepare socket */
	if (WSAStartup(0x0101, &wsaData) != 0) {
		LOG("Could not open Windows sockets\n");
		exit(2);
	}
#endif


	if (inet_pton(AF_INET6, LOCAL_IPV6_ADDR, &local_addr) <= 0) {
		LOG("Cannot convert IPv6 address\n");
		exit(1);
	}

	/* parse input parameters */
	while ((op = getopt(argc, argv, "Dv?")) != -1) {
		switch (op) {
#ifndef WIN32
			case 'D': daemon_opt = 1; break;
#endif
			case 'v': verbose_opt = 1; break;
			case '?': usage();
		}
	}


#ifndef WIN32
	/* daemonize process */
	if (daemon_opt) {
		daemonize_posix();
	}
#endif

	session_table_init(&sessions);
	srand(time(NULL) + clock());

#ifdef WIN32
	return main_loop_win(verbose_opt);
#else 
	return main_loop_posix(verbose_opt);
#endif

}





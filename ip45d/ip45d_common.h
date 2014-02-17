


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

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
#include <netinet/in.h>
#include <linux/if.h>
#endif

#ifdef __APPLE__
#include <net/if.h>
#endif

#include <ip45.h>
#include "session_table.h"


extern unsigned char local_addr[16];
extern struct session_table_t sessions;


uint16_t inet_cksum(char *addr, int len);

/* generates the random SID */
void mksid(struct in45_sid *sid);


/* process IP45 packet and prepare it as IPv6 packet*/
/* !1 - we expect that ipv6 buffer is big enough to handle data */
ssize_t ip45_to_ipv6(struct sockaddr_in *peer45_addr, char *ip45pkt, ssize_t len45, char *ip6pkt);

/* process IPv6 packet and prepare it as IP45 packet*/
/* !1 - we expect that ipv6 buffer is big enough to handle data */
ssize_t ipv6_to_ip45(char *ip6pkt, ssize_t len6, char *ip45pkt, struct sockaddr_in *peer45_addr);


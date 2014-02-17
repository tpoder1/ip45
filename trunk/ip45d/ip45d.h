

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
#include <stdint.h>
#include <fcntl.h>
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
#include <netinet/in.h>
#include <linux/if.h>
#endif

#ifdef __APPLE__
#include <net/if.h>
#endif

#include <ip45.h>


#define PKT_BUF_SIZE 2600
#define VERSION "$LastChangedRevision: 166 $"

#define LOG(fmt, ...) printf(fmt, ##__VA_ARGS__);
#define DEBUG(fmt, ...) printf(fmt, ##__VA_ARGS__);

#define LOCAL_IPV6_ADDR "0:0:0:0:0:1:0:0"
#define LOCAL_IPV6_MASKLEN 8






#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

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
#endif

#ifdef __linux 
#include <netinet/in.h>
#endif

#ifdef __APPLE__
#include <netinet/in.h>
#endif

#include <ip45.h>

struct session_entry_t  {
	uint64_t init_s45addr[2];
	uint64_t init_d45addr[2];
	uint64_t last_s45addr[2];
	uint64_t last_d45addr[2];
	uint16_t last_45port;
	uint8_t proto;
	uint16_t sport;
	uint16_t dport;
	struct in45_sid sid;
	struct session_entry_t *next;
} sesion_entry; 

struct session_table_t {
	struct session_entry_t *head;
	int items;
} session_table;

void session_table_init(struct session_table_t *table);
struct session_entry_t *session_table_add(struct session_table_t *table, struct session_entry_t *entry);
struct session_entry_t* session_table_lookup_sid(struct session_table_t *table, struct in45_sid *sid);
struct session_entry_t* session_table_lookup(struct session_table_t *table, 
	uint16_t sport, uint16_t dport, uint8_t proto);
	

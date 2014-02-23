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
#ifdef WIN32
#include "ip45d_win.h"
#else 
#include "ip45d_posix.h"
#endif
#include "session_table.h"
#include "inet_ntop45.h"


/* global variables  from ip45d_common.h */
unsigned char local_addr[16];
struct session_table_t sessions;


void usage(void) {
	printf("IP45 daemon version %s, package version: %s\n", VERSION, PKG_VERSION);
	printf("Usage:\n");
	printf("ip45d [ -D  ] [ -v ] \n");
	printf(" -D : daemonize process - only on POSIX (non WINDOWS) platform\n");
	printf(" -v : provide more debug information\n");
	exit(1);
}

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



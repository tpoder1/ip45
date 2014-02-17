

#include "ip45d.h"
#include "ip45d_common.h"
#include "session_table.h"
#include "inet_ntop45.h"


/* initialize output socket */
int init_sock_posix() {

	int sock;
	struct sockaddr_in ls; 
#ifdef __linux
	int yes = 1;
#endif

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {   
		perror("sock socket");
		return -1;
	}

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
		perror("bind"); 
		return -1;
	}
	
	return sock;
}

/* POSIX only : daemonize process */
void daemonize_posix(void) {
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
	if ((sockfd = init_sock_posix()) < 0) {
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
		
				DEBUG("Received IP45 packet %s->{me}, sid %08x.%08x.%08x.%08x, proto %d\n", 
					saddr,  
					(unsigned int)ntohl((unsigned int)ip45h->sid.s45_sid32[0]), 
					(unsigned int)ntohl((unsigned int)ip45h->sid.s45_sid32[1]), 
					(unsigned int)ntohl((unsigned int)ip45h->sid.s45_sid32[2]), 
					(unsigned int)ntohl((unsigned int)ip45h->sid.s45_sid32[3]),
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


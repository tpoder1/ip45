/*

  IP45 Project - http://ip45.org

  Copyright (C) 2012 - 2014,  Tomas Podermanski

  This code can be redistributed and/or modified under the terms of 
  the GNU General Public License as published by the Free Software 
  Foundation, either version 3 of the License, or (at your option) 
  any later version, see <http://www.gnu.org/licenses/>.

*/


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

/* build the ICMPv6 packets (IPv6 + ICMPv6 part) */
/* the buffer have to contain enough space to   */
/* build the requested packet including the body part */
/* the packet have to have prepared src and dst address */
int build_icmp6_pkt(char *pkt, unsigned char type, unsigned char code, char *body, int body_len);

/* build the TCP RST packet */
/* the buffer have to contain enough space to   */
/* build the requested packet including the body part */
int build_tcp_rst(char *pkt);


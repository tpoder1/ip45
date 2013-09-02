
/* inpired by linux kernel header file if_ether.h */


#define ETH_ALEN	6	/* Octets in one ethernet addr   */

#define ETH_P_IPV6	0x86DD /* IPv6 */
#define ETH_P_IP	0x0800 /* IPv4 */


struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr */
	unsigned char	h_source[ETH_ALEN];	/* source ether addr    */
	uint16_t		h_proto;			/* packet type ID field */
};


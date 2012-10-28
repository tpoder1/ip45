/*
 * IP45: IP45 gateway translation module
 * (c) 2012 tpoder@cis.vutbr.cz
 */

#ifndef _IPT_IP45_H
#define _IPT_IP45_H

#define IPT_IP45_INNER "inner-prefix"
#define IPT_IP45_OUTER "outer-addr"
#define IPT_IP45_LOG "log"

#define IPT_IP45_OPT_INNER 0x01
#define IPT_IP45_OPT_OUTER 0x02
#define IPT_IP45_OPT_LOG   0x04

struct ipt_ip45_info {
	struct in_addr		outer;			/* The external IP adress */
	struct in_addr		inner;			/* The internal network address */
	u_int16_t		inner_length;	/* The internal prefix length */
	u_int16_t   	ip45flags;		/* Some flags */
};

extern void _init(void);

#endif /*_IPT_IP45_H*/

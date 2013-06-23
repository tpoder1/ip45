/*
 * IP45: IP45 gateway translation module
 * (c) 2012 tpoder@cis.vutbr.cz
 */

#ifndef _IPT_IP45_H
#define _IPT_IP45_H

#define IPT_IP45_DOWNSTREAM "downstream-prefix"
#define IPT_IP45_UPSTREAM "upstream-addr"
#define IPT_IP45_LOG "log"

#define IPT_IP45_OPT_DOWNSTREAM 0x01
#define IPT_IP45_OPT_UPSTREAM 0x02
#define IPT_IP45_OPT_LOG   0x04

struct ipt_ip45bgw_info {
	u_int32_t		upstream;			/* The external - upstream IP adress */
	u_int32_t		downstream;			/* The internal - downstream network address  */
	u_int16_t		downstream_len;	/* The internal prefix length */
	u_int16_t   	ip45flags;		/* Some flags */
};

extern void _init(void);

#endif /*_IPT_IP45_H*/

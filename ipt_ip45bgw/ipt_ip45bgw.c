/*
 * IP45: 
 * inspired by MAP66 by sven-ola()gmx.de
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/ip.h>

#include "ip45.h"
#include "ipt_ip45bgw.h"

MODULE_AUTHOR("Tomas Podermanski <tpoder@cis.vutbr.cz>");
MODULE_DESCRIPTION("Xtables: IP45 - IP45 Border Gateway Module");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#error "The module is not supported on this kernel. Use >= 2.6.28"
#endif

#define NIP45FMT "%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d"
#define NIP45QUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[4], \
    ((unsigned char *)&addr)[5], \
    ((unsigned char *)&addr)[6], \
    ((unsigned char *)&addr)[7], \
    ((unsigned char *)&addr)[8], \
    ((unsigned char *)&addr)[9], \
    ((unsigned char *)&addr)[10], \
    ((unsigned char *)&addr)[11]

#define NIPFMT "%d.%d.%d.%d"
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static void ip45bgw_log(
	char str[], 
	struct ip45hdr *ip45h)
{
	printk(KERN_INFO "NF IP45: %s " NIPFMT " -> " NIPFMT " [IP45 " NIP45FMT "/%d -> " NIP45FMT "/%d] [SID:%lX] \n", str,
			NIPQUAD(ip45h->saddr), NIPQUAD(ip45h->daddr), 
			NIP45QUAD(ip45h->s45stck), ip45h->s45mark,
			NIP45QUAD(ip45h->d45stck), ip45h->d45mark,
			(unsigned long)ip45h->sid);

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static unsigned int ip45bgw_tg(struct sk_buff *skb, const struct xt_action_param *par) {
#else
static unsigned int ip45bgw_tg(struct sk_buff *skb, const struct xt_target_param *par) {
#endif
	struct ip45hdr *ip45h = (struct ip45hdr *)ip_hdr(skb);
	const struct ipt_ip45bgw_info *info = (struct ipt_ip45bgw_info *)par->targinfo;
	u_int32_t downstream, upstream;
	int shlen = (32 - info->downstream_len) / 8; /* number of octets to shift */
	int log = IPT_IP45_OPT_LOG & info->ip45flags;


	if (!skb_make_writable(skb, sizeof(struct ip45hdr))) {
		pr_devel("IP45: unwriteable, dropped\n");
		return NF_DROP;
	}

	/* check values in header */
	if (!is_ip45_pkt(ip45h)) {
		printk(KERN_ERR "IP45: invalid IP45 packet\n");
		return NF_DROP;
	}


	if ( log ) {
		ip45bgw_log("INPUT", ip45h);
	}
	
	memcpy(&downstream, &info->downstream, sizeof(downstream));
	memcpy(&upstream, &info->upstream, sizeof(upstream));
	
	

	/* test whether the source address is part og downstream prefix  -> update return path */
	/* shift address to right (32 - masklen) / 4 */
	if ( (ip45h->saddr << (32 - info->downstream_len) ) == (downstream << (32 - info->downstream_len)) ) {
		u_int32_t oldip = ip45h->saddr;

		/* increase smark */
		ip45h->s45mark += shlen;
		/* copy shlen bytes from source IP address to the 
 		* s45mark position (from the end) to s45stck */
		if (ip45h->s45mark < sizeof(struct in45_stck))  {
			memcpy((char *)&ip45h->s45stck + sizeof(struct in45_stck) - ip45h->s45mark, 
					(char *)&ip45h->saddr - shlen , shlen);
			ip45h->saddr = upstream;
			csum_replace4(&ip45h->check1, oldip, ip45h->saddr);
		} else {
			printk(KERN_ERR "IP45: s45mark reached the maximum value : %d/%d\n", 
						ip45h->s45mark, sizeof(struct in45_stck));
			return NF_DROP;
		}

	}

	/* test whether the destination address is upstream address 
  	*  -> the packet goes from the upstream (public) 
	*     network to the donwstream (private) network
	*  -> update destination addr by assebling from ip45 
	*     part (on the mark position) and prefix defined by rule  
 	*/
	if ( ip45h->daddr == upstream ) {
		u_int8_t *d45stck = (u_int8_t *)&ip45h->d45stck;
		u_int8_t *daddr = (u_int8_t *)&ip45h->daddr;
		u_int32_t oldip = ip45h->daddr;

		if (ip45h->d45mark > 0)  {
			// if dmark is set to 0 we have already processed all levels of IP45 border gateway
			memcpy(daddr, &downstream, sizeof(struct in_addr) - shlen);
			memcpy(daddr + sizeof(struct in_addr) - shlen, 
					d45stck + sizeof(struct in45_stck) - ip45h->d45mark, shlen);
			ip45h->d45mark -= shlen;
			csum_replace4(&ip45h->check1, oldip, ip45h->daddr);
		}
	}

	if ( log ) {
		ip45bgw_log("OUTPUT", ip45h);
	}

	return XT_CONTINUE;
}

static bool ip45bgw_tg_check(const struct xt_tgchk_param *par) {
	const struct ipt_ip45bgw_info *info = par->targinfo;

	if ( (IPT_IP45_OPT_DOWNSTREAM & info->ip45flags) == 0 || (IPT_IP45_OPT_UPSTREAM & info->ip45flags) == 0 ) {
		printk("IP45: you must specify both --" IPT_IP45_DOWNSTREAM " and --" IPT_IP45_UPSTREAM "\n");
		return false;
    }
	return true;
}

static struct xt_target ip45bgw_tg_reg __read_mostly = {
	.name 		= "ip45bgw",
	.target 	= ip45bgw_tg,
	.checkentry	= (void *)ip45bgw_tg_check,
	.destroy	= NULL,
	.family		= NFPROTO_IPV4,
	.targetsize	= sizeof(struct ipt_ip45bgw_info),
	.table		= "mangle",
	.hooks		= (1 << NF_INET_POST_ROUTING) | (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_FORWARD),
	.me 		= THIS_MODULE,
};

static int __init ip45bgw_tg_init(void)
{
	return xt_register_target(&ip45bgw_tg_reg);
}

static void __exit ip45bgw_tg_exit(void)
{
	xt_unregister_target(&ip45bgw_tg_reg);
}

module_init(ip45bgw_tg_init);
module_exit(ip45bgw_tg_exit);

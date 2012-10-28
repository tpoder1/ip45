/*
 * IP45: 
 * inspired by MAP66 by sven-ola()gmx.de
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/ip.h>

#include "ip45.h"
#include "ipt_IP45.h"

MODULE_AUTHOR("Tomas Podermanski <tpoder@cis.vutbr.cz>");
MODULE_DESCRIPTION("Xtables: IP45 - IP45 point of attachment translation module");
MODULE_LICENSE("GPL");


#define NIP45FMT "%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d.%d"
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
    ((unsigned char *)&addr)[11], \
    ((unsigned char *)&addr)[12], \
    ((unsigned char *)&addr)[13], \
    ((unsigned char *)&addr)[14], \
    ((unsigned char *)&addr)[15]

#define NIPFMT "%d.%d.%d.%d"
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static void ip45_log(
	char str[], 
	struct ip45hdr *ip45h)
{
	printk(KERN_INFO "NF IP45: %s " NIPFMT " -> " NIPFMT " [IP45 " NIP45FMT " -> " NIP45FMT "] [SID:%X] \n", str,
			NIPQUAD(ip45h->saddr), NIPQUAD(ip45h->daddr), 
			NIP45QUAD(ip45h->d45addr), NIP45QUAD(ip45h->s45addr),
			ip45h->sid);

}

static unsigned int ip45_tg(
	struct sk_buff *skb,
	const struct xt_target_param *par)
{
	struct ip45hdr *ip45h = (struct ip45hdr *)ip_hdr(skb);
	const struct ipt_ip45_info *info = par->targinfo;
	u_int32_t inner, outer;
	int shlen = (32 - info->inner_length) / 8;
	int log = IPT_IP45_OPT_LOG & info->ip45flags;


	if (!skb_make_writable(skb, sizeof(struct ip45hdr))) {
		pr_devel("IP45: unwriteable, dropped\n");
		return NF_DROP;
	}

	/* check values in header */
	if (ip45h->majorv != 4 || ip45h->minorv !=5 || ip45h->protocol != IPPROTO_IP45) {
		printk(KERN_ERR "IP45: invalid IP45 packet\n");
		return NF_DROP;
	}


	if ( log ) {
		ip45_log("INPUT", ip45h);
	}
	
	memcpy(&inner, &info->inner, sizeof(inner));
	memcpy(&outer, &info->outer, sizeof(outer));

	/* test whether the source address is part og inner prefix  -> update return path */
	/* shift address to right (32 - masklen) / 4 */
	if ( (ip45h->saddr << (32 - info->inner_length) ) == (inner << (32 - info->inner_length)) ) {
		u_int8_t *s45addr = (u_int8_t *)&ip45h->s45addr;
		u_int32_t oldip = ip45h->saddr;
		
		ip45h->smark += shlen;
		memcpy(s45addr + 12 - ip45h->smark , &outer, sizeof(outer));
		ip45h->saddr = outer;
		csum_replace4(&ip45h->check, oldip, ip45h->saddr);
	}

	/* test whether the destination address is outer address 
  	*  -> the packet goes from the upstream (public) 
	*     network to the donwstream (private) network
	*  -> update destination addr by assebling from ip45 
	*     part (on the mark position) and prefix defined by rule  
 	*/
	if ( ip45h->daddr == outer ) {
		u_int8_t *d45addr = (u_int8_t *)&ip45h->d45addr;
		u_int8_t *daddr = (u_int8_t *)&ip45h->daddr;
		u_int32_t oldip = ip45h->daddr;

		if (ip45h->dmark > 0)  {
			// if fwdlen is set to 0 we have already processed all levels of IP45 attache points
			memcpy(daddr, &inner, 4 - shlen);
			memcpy(daddr + 4 - shlen, d45addr + 16 - (int)ip45h->dmark, shlen);
			ip45h->dmark -= shlen;
			csum_replace4(&ip45h->check, oldip, ip45h->daddr);
		}
	}

	if ( log ) {
		ip45_log("OUTPUT", ip45h);
	}

	return XT_CONTINUE;
}

static bool ip45_tg_check(
	const struct xt_tgchk_param *par)
{
	const struct ipt_ip45_info *info = par->targinfo;

	if ( (IPT_IP45_OPT_INNER & info->ip45flags) == 0 || (IPT_IP45_OPT_OUTER & info->ip45flags) == 0 ) {
		printk("IP45: you must specify both --" IPT_IP45_INNER " and --" IPT_IP45_OUTER "\n");
		return false;
    }
	return true;
}

static struct xt_target ip45_tg_reg __read_mostly = {
	.name 		= "IP45",
	.target 	= ip45_tg,
	.checkentry	= ip45_tg_check,
	.destroy	= NULL,
	.family		= NFPROTO_IPV4,
	.targetsize	= sizeof(struct ipt_ip45_info),
	.table		= "mangle",
	.hooks		= (1 << NF_INET_POST_ROUTING) | (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_FORWARD),
	.me 		= THIS_MODULE,
};

static int __init ip45_tg_init(void)
{
	return xt_register_target(&ip45_tg_reg);
}

static void __exit ip45_tg_exit(void)
{
	xt_unregister_target(&ip45_tg_reg);
}

module_init(ip45_tg_init);
module_exit(ip45_tg_exit);

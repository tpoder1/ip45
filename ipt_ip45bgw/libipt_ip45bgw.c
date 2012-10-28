/*
 * Inspired by MAP66 by sven-ola()gmx.de
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>


#define IPTABLES_VERSION_CMP(a,b,c) (((a) << 16) + ((b) << 8) + (c))

#if IPTABLES_VERSION_CODE < IPTABLES_VERSION_CMP(1,4,0)
#  include <iptables.h>
#  define xt_entry_target ipt_entry_target
#  define void_entry struct ipt_entry
#  define void_ip struct ipt_ip
#else
#  include <xtables.h>
#  define void_entry void
#  define void_ip void
#endif

#if IPTABLES_VERSION_CODE < IPTABLES_VERSION_CMP(1,4,1)
#  define xtables_target iptables_target
#  define XTABLES_VERSION IPTABLES_VERSION
#  define xtables_register_target register_target
#endif

#if IPTABLES_VERSION_CODE < IPTABLES_VERSION_CMP(1,4,3)
#  define xtables_error exit_error
#  define  xtables_check_inverse check_inverse
#  define NFPROTO_IPV PF_INET
#endif

#ifndef XT_ALIGN
#  define XT_ALIGN IPT_ALIGN
#endif

#include "ipt_ip45bgw.h"

static void ip45bgw_help(void)
{
	printf(
"IP45 target options\n"
"  --" IPT_IP45_UPSTREAM " upstream IP address\n"
"  --" IPT_IP45_DOWNSTREAM " downstream IP prefix/length\n"
"  --log                       log every packet (only for debuging)\n"
"\n"
"Example:\n"
"\n"
"iptables -t mangle -I POSTROUTING  -o eth0 -p 155 -j ip45bgw --" IPT_IP45_DOWNSTREAM " 192.168.0.0/24 --" IPT_IP45_UPSTREAM " 147.229.240.243\n"
"iptables -t mangle -I PREROUTING   -i eth0 -p 155 -j ip45bgw --" IPT_IP45_DOWNSTREAM " 192.168.0.0/24 --" IPT_IP45_UPSTREAM " 147.229.240.243\n");
}

static int ip45bgw_parse(
	int c,
	char **argv,
	int invert,
	unsigned int *flags,
	const void_entry *entry,
	struct xt_entry_target **target)
{
	int i;
	char *p;
	u_int32_t addr;
	struct ipt_ip45bgw_info* info = (struct ipt_ip45bgw_info*)(*target)->data;
	
	switch(c) {
		case '1':
			if (!optarg) {
				xtables_error(PARAMETER_PROBLEM, "--" IPT_IP45_UPSTREAM ": You must specify a value");
			}
			if (xtables_check_inverse(optarg, &invert, NULL, 0
#if IPTABLES_VERSION_CODE >= IPTABLES_VERSION_CMP(1,4,6)
				,argv
#endif
			)) {
				xtables_error(PARAMETER_PROBLEM, "Unexpected `!' after --" IPT_IP45_UPSTREAM);
			}

			if ((IPT_IP45_OPT_UPSTREAM & *flags) != 0) {
                xtables_error(PARAMETER_PROBLEM, "Multiple --" IPT_IP45_UPSTREAM " not supported");
            }

			if (inet_pton(AF_INET, optarg, &info->upstream) != 1) {
				xtables_error(PARAMETER_PROBLEM, "Invalid IP address in --" IPT_IP45_UPSTREAM ": \"%s\"", optarg);
			}

            *flags |= IPT_IP45_OPT_UPSTREAM;
            info->ip45flags |= IPT_IP45_OPT_UPSTREAM;
			return 1;
		break;
		case '2':
			if (!optarg) {
				xtables_error(PARAMETER_PROBLEM, "--" IPT_IP45_DOWNSTREAM ": You must specify a value");
			}
			if (xtables_check_inverse(optarg, &invert, NULL, 0
#if IPTABLES_VERSION_CODE >= IPTABLES_VERSION_CMP(1,4,6)
				,argv
#endif
			)) {
				xtables_error(PARAMETER_PROBLEM, "Unexpected `!' after --" IPT_IP45_DOWNSTREAM);
			}

			if ((p = strchr(optarg, '/')) == NULL) {
				xtables_error(PARAMETER_PROBLEM, "Missing '/' character in --" IPT_IP45_DOWNSTREAM ": \"%s\"", optarg);
			}

			if ((IPT_IP45_OPT_DOWNSTREAM & *flags) != 0) {
                xtables_error(PARAMETER_PROBLEM, "Multiple --" IPT_IP45_DOWNSTREAM " not supported");
            }

			*p = '\0';
			if (inet_aton(optarg, &info->downstream) != 1) {
				xtables_error(PARAMETER_PROBLEM, "Invalid IP address in --" IPT_IP45_DOWNSTREAM ": \"%s\"", optarg);
			}

			memcpy(&addr, &info->downstream, sizeof(addr));

			i = atoi(p + 1);
			if (i  != 8 && i != 16 && i != 24) {
				xtables_error(PARAMETER_PROBLEM, "Invalid prefix length in --" IPT_IP45_DOWNSTREAM ": \"%s\" (use /8, /16, /24)", p);
			}
			info->downstream_len = i;

            *flags |= IPT_IP45_OPT_DOWNSTREAM;
            info->ip45flags |= IPT_IP45_OPT_DOWNSTREAM;
			return 1;
		break;
		case '3':
            *flags |= IPT_IP45_OPT_LOG;
            info->ip45flags |= IPT_IP45_OPT_LOG;
			return 1;
		break;
	}
	return 0;
}

static void ip45bgw_check(unsigned int flags)
{
	if ( (IPT_IP45_OPT_DOWNSTREAM & flags) == 0 || (IPT_IP45_OPT_UPSTREAM & flags) == 0 ) {
		xtables_error(PARAMETER_PROBLEM, "You must specify both --" IPT_IP45_DOWNSTREAM " and --" IPT_IP45_UPSTREAM);
	}
}

static void ip45bgw_save(
	const void_ip *ip,
	const struct xt_entry_target *target)
{
	char s[50+1];
	const struct ipt_ip45bgw_info* info = (struct ipt_ip45bgw_info*)target->data;
	if (0 != (IPT_IP45_OPT_UPSTREAM & info->ip45flags)) {
		printf("--" IPT_IP45_UPSTREAM " %s ", inet_ntop(AF_INET, &info->upstream, s, sizeof(s)));
	}
	if (0 != (IPT_IP45_OPT_DOWNSTREAM & info->ip45flags)) {
		printf("--" IPT_IP45_DOWNSTREAM " %s/%d ", inet_ntop(AF_INET, &info->downstream, s, sizeof(s)), info->downstream_len);
	}
	if (0 != (IPT_IP45_OPT_LOG & info->ip45flags)) {
		printf("--" IPT_IP45_LOG " ");
	}
}

static struct option ip45bgw_opts[] = {
	{ .name = IPT_IP45_UPSTREAM, .has_arg = 1, .flag = NULL, .val = '1' },
	{ .name = IPT_IP45_DOWNSTREAM, .has_arg = 1, .flag = NULL, .val = '2' },
	{ .name = IPT_IP45_LOG, .has_arg = 0, .flag = NULL, .val = '3' },
	{ .name = NULL }
};

static struct xtables_target ip45bgw_tg_reg = {
	.name 		= "ip45bgw",
	.version	= XTABLES_VERSION,
#if IPTABLES_VERSION_CODE >= IPTABLES_VERSION_CMP(1,4,1)
	.family		= NFPROTO_IPV4,
#endif
	.size		= XT_ALIGN(sizeof(struct ipt_ip45bgw_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_ip45bgw_info)),
	.help		= ip45bgw_help,
	.parse		= ip45bgw_parse,
	.final_check	= ip45bgw_check,
	.save		= ip45bgw_save,
	.extra_opts	= ip45bgw_opts,
};

void _init(void)
{
	xtables_register_target(&ip45bgw_tg_reg);
}

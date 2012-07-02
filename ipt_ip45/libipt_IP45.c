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

#include "ipt_IP45.h"

static void ip45_help(void)
{
	printf(
"IP45 target options\n"
"  --" IPT_IP45_OUTER " outer IP address\n"
"  --" IPT_IP45_INNER " inner IP prefix/length\n"
"  --log                       log every packet (only for debuging)\n"
"\n"
"Example:\n"
"\n"
"iptables -t mangle -I POSTROUTING  -o eth0 -p 155 -j IP45 --" IPT_IP45_INNER " 192.168.0.0/24 --" IPT_IP45_OUTER " 147.229.240.243\n"
"iptables -t mangle -I PREROUTING   -i eth0 -p 155 -j IP45 --" IPT_IP45_INNER " 192.168.0.0/24 --" IPT_IP45_OUTER " 147.229.240.243\n");
}

static int ip45_parse(
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
	struct ipt_ip45_info* info = (struct ipt_ip45_info*)(*target)->data;
	
	switch(c) {
		case '1':
			if (!optarg) {
				xtables_error(PARAMETER_PROBLEM, "--" IPT_IP45_OUTER ": You must specify a value");
			}
			if (xtables_check_inverse(optarg, &invert, NULL, 0
#if IPTABLES_VERSION_CODE >= IPTABLES_VERSION_CMP(1,4,6)
				,argv
#endif
			)) {
				xtables_error(PARAMETER_PROBLEM, "Unexpected `!' after --" IPT_IP45_OUTER);
			}

			if ((IPT_IP45_OPT_OUTER & *flags) != 0) {
                xtables_error(PARAMETER_PROBLEM, "Multiple --" IPT_IP45_OUTER " not supported");
            }

			if (inet_pton(AF_INET, optarg, &info->outer) != 1) {
				xtables_error(PARAMETER_PROBLEM, "Invalid IP address in --" IPT_IP45_OUTER ": \"%s\"", optarg);
			}

            *flags |= IPT_IP45_OPT_OUTER;
            info->ip45flags |= IPT_IP45_OPT_OUTER;
			return 1;
		break;
		case '2':
			if (!optarg) {
				xtables_error(PARAMETER_PROBLEM, "--" IPT_IP45_INNER ": You must specify a value");
			}
			if (xtables_check_inverse(optarg, &invert, NULL, 0
#if IPTABLES_VERSION_CODE >= IPTABLES_VERSION_CMP(1,4,6)
				,argv
#endif
			)) {
				xtables_error(PARAMETER_PROBLEM, "Unexpected `!' after --" IPT_IP45_INNER);
			}

			if ((p = strchr(optarg, '/')) == NULL) {
				xtables_error(PARAMETER_PROBLEM, "Missing '/' character in --" IPT_IP45_INNER ": \"%s\"", optarg);
			}

			if ((IPT_IP45_OPT_INNER & *flags) != 0) {
                xtables_error(PARAMETER_PROBLEM, "Multiple --" IPT_IP45_INNER " not supported");
            }

			*p = '\0';
			if (inet_aton(optarg, &info->inner) != 1) {
				xtables_error(PARAMETER_PROBLEM, "Invalid IP address in --" IPT_IP45_INNER ": \"%s\"", optarg);
			}

			memcpy(&addr, &info->inner, sizeof(addr));

			i = atoi(p + 1);
			if (i  != 8 && i != 16 && i != 24) {
				xtables_error(PARAMETER_PROBLEM, "Invalid prefix length in --" IPT_IP45_INNER ": \"%s\" (use /8, /16, /24)", p);
			}
			info->inner_length = i;

            *flags |= IPT_IP45_OPT_INNER;
            info->ip45flags |= IPT_IP45_OPT_INNER;
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

static void ip45_check(unsigned int flags)
{
	if ( (IPT_IP45_OPT_INNER & flags) == 0 || (IPT_IP45_OPT_OUTER & flags) == 0 ) {
		xtables_error(PARAMETER_PROBLEM, "You must specify both --" IPT_IP45_INNER " and --" IPT_IP45_OUTER);
	}
}

static void ip45_save(
	const void_ip *ip,
	const struct xt_entry_target *target)
{
	char s[50+1];
	const struct ipt_ip45_info* info = (struct ipt_ip45_info*)target->data;
	if (0 != (IPT_IP45_OPT_OUTER & info->ip45flags)) {
		printf("--" IPT_IP45_OUTER " %s", inet_ntop(AF_INET, &info->outer, s, sizeof(s)));
	}
	if (0 != (IPT_IP45_OPT_INNER & info->ip45flags)) {
		printf("--" IPT_IP45_INNER " %s/%d ", inet_ntop(AF_INET, &info->inner, s, sizeof(s)), info->inner_length);
	}
}

static struct option ip45_opts[] = {
	{ .name = IPT_IP45_OUTER, .has_arg = 1, .flag = NULL, .val = '1' },
	{ .name = IPT_IP45_INNER, .has_arg = 1, .flag = NULL, .val = '2' },
	{ .name = "log", .has_arg = 0, .flag = NULL, .val = '4' },
	{ .name = NULL }
};

static struct xtables_target ip45_tg_reg = {
	.name 		= "IP45",
	.version	= XTABLES_VERSION,
#if IPTABLES_VERSION_CODE >= IPTABLES_VERSION_CMP(1,4,1)
	.family		= NFPROTO_IPV4,
#endif
	.size		= XT_ALIGN(sizeof(struct ipt_ip45_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_ip45_info)),
	.help		= ip45_help,
	.parse		= ip45_parse,
	.final_check	= ip45_check,
	.save		= ip45_save,
	.extra_opts	= ip45_opts,
};

void _init(void)
{
	xtables_register_target(&ip45_tg_reg);
}

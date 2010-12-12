// Author: lex@realisticgroup.com (Alexey Lapitsky)

#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include "ipt_pdp.h"

static const struct option pdp_mt_opts[] = {
    {.name = "pdp-any", .has_arg = false, .val = '1'},
    {.name = "pdp-reserved", .has_arg = false, .val = '2'},
    {.name = "pdp-station-id", .has_arg = true, .val = '3'},
    {.name = "pdp-imsi", .has_arg = true, .val = '4'},
    {NULL},
};

static void pdp_mt_help(void)
{
    printf(
	    "pdp match options for PDP Create Context requests:\n"
	    " --pdp-any                 Match any request\n"
	    " --pdp-reserved            Match hardcoded list of station ids\n"
	    " --pdp-station-id num      Match particular Calling-Station-ID\n"
//	    " --pdp-imsi       num      Match particular 3GPP-IMSI\n"
	  );
}

static void pdp_mt_init(struct xt_entry_match *match)
{
    struct xt_pdp_mtinfo *info = (void *)match->data;
}

static int pdp_mt_parse(int c, char **argv, int invert,
	unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
    struct xt_pdp_mtinfo *info = (void *)(*match)->data;
    struct in_addr *addrs, mask;
    unsigned int naddrs;

    if (info->type != 0)
	xtables_error(PARAMETER_PROBLEM, "xt_pdp: "
		"You can use only one param per rule");

    switch (c) {
	case '1': 
	    *flags = info->type = PDP_ANY;
	    return true;

	case '2':
	    *flags = info->type = PDP_RESERVED;
	    return true;

	case '3': /* --station-id num */
	    if (strlen(optarg) > 12)
		xtables_error(PARAMETER_PROBLEM, "xt_pdp: "
			"Max parameter length is 12");
	    info->n = atoll(optarg);
	    *flags = info->type = PDP_STATION_ID;
	    return true;

	case '4': /* --imsi num */
	    if (strlen(optarg) > 15)
		xtables_error(PARAMETER_PROBLEM, "xt_pdp: "
			"Max parameter length is 15");
	    info->n = atoll(optarg);
	    *flags = info->type = PDP_IMSI;
	    return true;
    }

    return false;
}

static void pdp_mt_check(unsigned int flags)
{
    if (flags == 0)
	xtables_error(PARAMETER_PROBLEM, "pdp: You need to "
		"specify at least one parameter!");
}

static void pdp_mt_print(const void *entry,
	const struct xt_entry_match *match, int numeric)
{
    const struct xt_pdp_mtinfo *info = (const void *)match->data;
    switch (info->type) {
	case PDP_ANY:
	    printf("pdp-any");
	    return;
	case PDP_RESERVED:
	    printf("pdp-reserved");
	    return;
	case PDP_STATION_ID:
	    printf("pdp-station-id: %llu", (unsigned long long)info->n);
	    return;
	case PDP_IMSI:
	    printf("pdp-imsi: %llu", (unsigned long long)info->n);
	    return;
    }
    return;
}


static void pdp_mt_save(const void *entry,
	const struct xt_entry_match *match)
{
    const struct xt_pdp_mtinfo *info = (const void *)match->data;
    switch (info->type) {
	case PDP_ANY:
	    printf("--pdp-any ");
	    return;
	case PDP_RESERVED:
	    printf("--pdp-reserved ");
	    return;
	case PDP_STATION_ID:
	    printf("--pdp-station-id %llu ", (unsigned long long)info->n);
	    return;
	case PDP_IMSI:
	    printf("--pdp-imsi %llu ", (unsigned long long)info->n);
	    return;
    }

    return;

}

static struct xtables_match pdp_mt_reg = {
    .version       = XTABLES_VERSION,
    .name          = "pdp",
    .revision      = 0,
    .size          = XT_ALIGN(sizeof(struct xt_pdp_mtinfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_pdp_mtinfo)),
    .help          = pdp_mt_help,
    .init          = pdp_mt_init,
    .parse         = pdp_mt_parse,
    .final_check   = pdp_mt_check,
    .print         = pdp_mt_print,
    .save          = pdp_mt_save,
    .extra_opts    = pdp_mt_opts,
};

static void _init(void)
{
    xtables_register_match(&pdp_mt_reg);
}



// Author: lex@realisticgroup.com (Alexey Lapitsky)

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include "compat_xtables.h"

#include "ipt_pdp.h"
#include "whitelist.h"
#include "pdp.h"

/* return true if packet is matched. pdata - start of GTP header */
static bool match_pdp_packet(const void *pdata, uint16_t packet_len, const struct xt_pdp_mtinfo *info)
{
    struct gtp_hdr *h = (struct gtp_hdr*)pdata;
    uint32_t offs = sizeof(*h);
    uint8_t header_type;
    uint16_t len;
    bool whitelisted = false;

    /* Match only known types of PDP packets */
    if (h->flags != 0x32)
	return false;

    if (h->message_type != PDP_CREATE_CONTEXT_REQ)
	return false;

    /* check for "no more extension headers" */
    if (h->next_ext != 0x00)
	return false;

    if (info->type == PDP_ANY)
	return true;

    while((offs + 2 < packet_len) && (offs + 2 < (sizeof(*h) + ntohs(h->len))) && !whitelisted) {
	header_type = *(uint8_t *)(pdata + offs);
	len = 0;
	if (header_type >= 0b10000000) { // | type | length | value |
	    len = htons(*(uint16_t *)(pdata + offs + 1)) + 2; // +2 for length bytes
	    if (header_type == GTP_EXT_MSISDN) {
		//  printk(KERN_INFO "msisdn: %llu", msisdn_to_uint64(pdata + offs + 3, len - 2 ));
		whitelisted = pdp_stationid_match(msisdn_to_uint64(pdata + offs + 3, len - 2), info);
		return whitelisted;
	    }
	}
	else { // | type | value |
	    int i = 0;
	    for(; i < gtp_headers_size(); ++i) {
		if (gtp_headers[i].type == header_type) {
		    len = gtp_headers[i].length;
		    break;
		}
	    }
	}

	if (len <= 0)
	    return false;

	offs += len + 1; // +1 for header type

    }

    return whitelisted;
}


static bool pdp_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct iphdr *iph = ip_hdr(skb);
    const struct udphdr *udph;
    uint16_t len;

    if (iph->protocol != IPPROTO_UDP) return false;

    udph = (const void *)iph + ip_hdrlen(skb);
    if (udph->dest != 0x4b08) return false; // match only GTP Control port 2123

    len  = ntohs(udph->len) - sizeof(struct udphdr);

    return match_pdp_packet((void *)udph + sizeof(struct udphdr), len, par->matchinfo);
}

static int pdp_mt_check(const struct xt_mtchk_param *par)
{
    return 0;
}

static struct xt_match pdp_mt_reg[] __read_mostly = {
    {
	.name       = "pdp",
	.revision   = 0,
	.match      = pdp_mt,
	.checkentry = pdp_mt_check,
	.matchsize  = XT_ALIGN(sizeof(struct xt_pdp_mtinfo)),
	.me         = THIS_MODULE,
    },
};

static int __init pdp_mt_init(void)
{
    return xt_register_matches(pdp_mt_reg, ARRAY_SIZE(pdp_mt_reg));
}

static void __exit pdp_mt_exit(void)
{
    xt_unregister_matches(pdp_mt_reg, ARRAY_SIZE(pdp_mt_reg));
}

MODULE_AUTHOR("Alexey Lapitsky");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("PDP whitelist");

MODULE_ALIAS("xt_pdp");
MODULE_ALIAS("ipt_pdp");
MODULE_ALIAS("ip6t_pdp");
MODULE_ALIAS("arpt_pdp");
MODULE_ALIAS("ebt_pdp");

module_init(pdp_mt_init);
module_exit(pdp_mt_exit);

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
    uint32_t offs = sizeof(struct gtp_hdr);
    uint64_t msisdn = 0;
    uint64_t imsi = 0;
    uint8_t header_type;
    uint16_t len;
    bool matched = false;

    while((offs + 2 < packet_len) && !matched) {
      header_type = *(uint8_t *)(pdata + offs);
      len = 0;
      if (header_type >= 0b10000000) { // | type | length | value |
          len = htons(*(uint16_t *)(pdata + offs + 1)) + 2; // +2 for length bytes
          if (header_type == GTP_EXT_MSISDN) {
              msisdn = msisdn_to_uint64(pdata + offs + 3, len - 2 );
              if (info->type == PDP_ANY) {
                  matched = true;
              }
              else {
                  matched = pdp_stationid_match(msisdn, info);
              }
          }
      }
      else { // | type | value |
          int i = 0;

          if (header_type == GTP_EXT_IMSI) {
              imsi = imsi_to_uint64(pdata + offs + 1);
          }

          for(; i < gtp_headers_size(); ++i) {
              if (gtp_headers[i].type == header_type) {
                  len = gtp_headers[i].length;
                  break;
              }
          }
      }

      if (len <= 0)
          break;

      offs += len + 1; // +1 for header type

    }

    if (matched) {
        char * msg;
        switch (info->type) {
            case PDP_ANY        : msg = "any      "; break;
            case PDP_RESERVED   : msg = "reserved "; break;
            case PDP_STATION_ID : msg = "matched  "; break;
            default             : msg = "error";
        }

        printk(KERN_INFO "%s msisdn: %llu imsi: %llu\n", msg, msisdn, imsi) ;

    }

    return matched;
}


static bool pdp_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
    const struct iphdr *iph = ip_hdr(skb);
    const struct udphdr *udph;
    const struct gtp_hdr *gtph;
    uint16_t payload_len;
    bool matched = false;
    void * payload;

    if (iph->protocol != IPPROTO_UDP) return false;

    udph = (const void *)iph + ip_hdrlen(skb);
    if (udph->dest != 0x4b08) return false; // match only GTP Control port 2123

    gtph = (const void *)udph + sizeof(struct udphdr);
    if (gtph->flags != 0x32) return false; // Match only known types of PDP packets
    if (gtph->message_type != PDP_CREATE_CONTEXT_REQ) return false; // check for "no more extension headers"
    if (gtph->next_ext != 0x00) return false;

    payload_len = ntohs(udph->len) - sizeof(struct udphdr);
    payload = kmalloc(payload_len, GFP_KERNEL);
    if (skb_copy_bits(skb, sizeof(struct iphdr) + sizeof(struct udphdr), payload, payload_len) == 0){
        matched = match_pdp_packet(payload, payload_len, par->matchinfo);
    } else {
        printk(KERN_INFO "failed to copy payload") ;
    }
    kfree(payload);

    return matched;
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

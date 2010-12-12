// Author: lex@realisticgroup.com (Alexey Lapitsky)

#ifndef _LINUX_NETFILTER_XT_PDP_H
#define _LINUX_NETFILTER_XT_PDP_H 1

#define PDP_ANY        1
#define PDP_RESERVED   2
#define PDP_STATION_ID 3
#define PDP_IMSI       4

struct xt_pdp_mtinfo {
    uint64_t n, max_n;
    uint8_t type;
};

#endif /* _LINUX_NETFILTER_XT_PDP_H */


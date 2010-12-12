// Author: lex@realisticgroup.com (Alexey Lapitsky)

#ifndef _WHITELIST_H
#define _WHITELIST_H

#include <linux/netfilter.h>


struct wl_range {
    uint64_t min;
    uint64_t max;
};

extern struct wl_range wl_stationid[];
extern size_t wl_stationid_size(void);

#endif

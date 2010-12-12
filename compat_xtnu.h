#ifndef _COMPAT_XTNU_H
#define _COMPAT_XTNU_H 1

#include <linux/list.h>
#include <linux/netfilter/x_tables.h>
#include <linux/spinlock.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
typedef _Bool bool;
enum { false = 0, true = 1, };
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19)
typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;
#endif

struct flowi;
struct hh_cache;
struct module;
struct net_device;
struct rtable;
struct sk_buff;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
enum {
	NFPROTO_UNSPEC =  0,
	NFPROTO_IPV4   =  2,
	NFPROTO_ARP    =  3,
	NFPROTO_BRIDGE =  7,
	NFPROTO_IPV6   = 10,
	NFPROTO_DECNET = 12,
	NFPROTO_NUMPROTO,
};

struct xt_mtchk_param {
	const char *table;
	const void *entryinfo;
	const struct xt_match *match;
	void *matchinfo;
	unsigned int hook_mask;
	u_int8_t family;
};

struct xt_mtdtor_param {
	const struct xt_match *match;
	void *matchinfo;
	u_int8_t family;
};

struct xt_target_param {
	const struct net_device *in, *out;
	unsigned int hooknum;
	const struct xt_target *target;
	const void *targinfo;
	u_int8_t family;
};

struct xt_tgchk_param {
	const char *table;
	const void *entryinfo;
	const struct xt_target *target;
	void *targinfo;
	unsigned int hook_mask;
	u_int8_t family;
};

struct xt_tgdtor_param {
	const struct xt_target *target;
	void *targinfo;
	u_int8_t family;
};
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
struct xt_action_param {
	union {
		const struct xt_match *match;
		const struct xt_target *target;
	};
	union {
		const void *matchinfo, *targinfo;
	};
	const struct net_device *in, *out;
	int fragoff;
	unsigned int thoff, hooknum;
	u_int8_t family;
	bool hotdrop;
};
#endif

struct xtnu_match {
	/*
	 * Making it smaller by sizeof(void *) on purpose to catch
	 * lossy translation, if any.
	 */
	char name[sizeof(((struct xt_match *)NULL)->name) - 1 - sizeof(void *)];
	uint8_t revision;
	bool (*match)(const struct sk_buff *, struct xt_action_param *);
	int (*checkentry)(const struct xt_mtchk_param *);
	void (*destroy)(const struct xt_mtdtor_param *);
	struct module *me;
	const char *table;
	unsigned int matchsize, hooks;
	unsigned short proto, family;

	void *__compat_match;
};

struct xtnu_target {
	char name[sizeof(((struct xt_target *)NULL)->name) - 1 - sizeof(void *)];
	uint8_t revision;
	unsigned int (*target)(struct sk_buff **,
		const struct xt_action_param *);
	int (*checkentry)(const struct xt_tgchk_param *);
	void (*destroy)(const struct xt_tgdtor_param *);
	struct module *me;
	const char *table;
	unsigned int targetsize, hooks;
	unsigned short proto, family;

	void *__compat_target;
};

static inline struct xtnu_match *xtcompat_numatch(const struct xt_match *m)
{
	void *q;
	memcpy(&q, m->name + sizeof(m->name) - sizeof(void *), sizeof(void *));
	return q;
}

static inline struct xtnu_target *xtcompat_nutarget(const struct xt_target *t)
{
	void *q;
	memcpy(&q, t->name + sizeof(t->name) - sizeof(void *), sizeof(void *));
	return q;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19)
static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}
#endif

extern int xtnu_ip_local_out(struct sk_buff *);
extern int xtnu_ip_route_me_harder(struct sk_buff **, unsigned int);
extern int xtnu_skb_make_writable(struct sk_buff **, unsigned int);
extern int xtnu_register_match(struct xtnu_match *);
extern int xtnu_ip_route_output_key(void *, struct rtable **, struct flowi *);
extern void xtnu_unregister_match(struct xtnu_match *);
extern int xtnu_register_matches(struct xtnu_match *, unsigned int);
extern void xtnu_unregister_matches(struct xtnu_match *, unsigned int);
extern int xtnu_register_target(struct xtnu_target *);
extern void xtnu_unregister_target(struct xtnu_target *);
extern int xtnu_register_targets(struct xtnu_target *, unsigned int);
extern void xtnu_unregister_targets(struct xtnu_target *, unsigned int);
extern struct xt_match *xtnu_request_find_match(unsigned int,
	const char *, uint8_t);
extern int xtnu_neigh_hh_output(struct hh_cache *, struct sk_buff *);
extern void xtnu_csum_replace2(__u16 __bitwise *, __be16, __be16);
extern void xtnu_csum_replace4(__u16 __bitwise *, __be32, __be32);
extern void xtnu_proto_csum_replace4(__u16 __bitwise *, struct sk_buff *,
	__be32, __be32, bool);
extern int xtnu_skb_linearize(struct sk_buff *);

extern void *HX_memmem(const void *, size_t, const void *, size_t);

#endif /* _COMPAT_XTNU_H */

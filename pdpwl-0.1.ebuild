# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/net-firewall/ipset/ipset-4.4.ebuild,v 1.1 2010/10/14 15:41:22 pva Exp $

EAPI="2"

inherit eutils versionator toolchain-funcs linux-mod

DESCRIPTION="PDP Create Context matcher for iptables, can match and whitelist
GTP packets by Station-Id."
HOMEPAGE="http://realisticgroup.com/"
# SRC_URI="http://realisticgroup.com/${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="amd64 x86"
IUSE="modules"

RDEPEND=">=net-firewall/iptables-1.4.4"
DEPEND="${RDEPEND}"

# module fun
BUILD_TARGETS="all"
MODULE_NAMES="pdpwl(kernel/net/ipv4/netfilter:${S}) compat_xtables(kernel/net/ipv4/netfilter:${S})"
CONFIG_CHECK="NETFILTER"
ERROR_CFG="pdpwl requires netfilter support in your kernel."

pkg_setup() {
	get_version

	build_modules=0
	if use modules; then
		if linux_config_src_exists && linux_chkconfig_builtin "MODULES" ; then
			build_modules=1
			einfo "Modular kernel detected, will build kernel modules"
		else
			eerror "Nonmodular kernel detected"
		fi
	fi

	[[ ${build_modules} -eq 1 ]] && linux-mod_pkg_setup
	myconf="${myconf} PREFIX="
	myconf="${myconf} LIBDIR=/$(get_libdir)/xtables"
	myconf="${myconf} INCDIR=/usr/include"
	export myconf
}

src_compile() {
	einfo "Building userspace"
	emake \
		CC="$(tc-getCC)" \
		COPT_FLAGS="${CFLAGS}" \
		LDFLAGS="${LDFLAGS}" \
		${myconf} \
		libxt_pdp || die "failed to build"

	if [[ ${build_modules} -eq 1 ]]; then
		einfo "Building kernel modules"
		linux-mod_src_compile || die "failed to build modules"
	fi
}

src_install() {
	einfo "Installing userspace"
	emake DESTDIR="${D}" ${myconf} binaries_install || die "failed to package"

	if [[ ${build_modules} -eq 1 ]]; then
		einfo "Installing kernel modules"
#		export KERNELDIR="${KERNEL_DIR}"
		linux-mod_src_install
	fi
}

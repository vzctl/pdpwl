# Author: lex@realisticgroup.com (Alexey Lapitsky)

obj-m := pdpwl.o compat_xtables.o
pdpwl-objs := ipt_pdp.o pdp.o whitelist.o

all: libxt_pdp modules

libxt_pdp: 
	$(CC) -shared libxt_pdp.c -fPIC -o libxt_pdp.so

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) KBUILD_EXTMOD=$(PWD) modules


$(DESTDIR)$(LIBDIR)/libxt_pdp.so: libxt_pdp
	@[ -d $(DESTDIR)$(LIBDIR) ] || mkdir -p $(DESTDIR)$(LIBDIR)
	cp libxt_pdp.so $@

binaries_install: $(DESTDIR)$(LIBDIR)/libxt_pdp.so

modules_install: modules

install: binaries_install modules_install

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean; rm *.so

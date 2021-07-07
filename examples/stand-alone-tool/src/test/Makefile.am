MAINTAINERCLEANFILES = $(srcdir)/Makefile.in env.sh
CLEANFILES = test*.log test*.trs test*.out *.pcap-dist

TESTS = test.sh

BUILT_SOURCES = env.sh

env.sh:
	echo "export PATH=\"\$$PATH:@DNSJIT_ROOT@/bin\"" >"$@"
	echo "export LUA_CPATH=\"@DNSJIT_ROOT@/lib/lua/5.1/?.so;;\"" >>"$@"
	echo "export LUA_PATH=\"@DNSJIT_ROOT@/share/lua/5.1/?.lua;;\"" >>"$@"

test.sh: env.sh dns.pcap-dist

.pcap.pcap-dist:
	cp "$<" "$@"

EXTRA_DIST = $(TESTS) dns.pcap

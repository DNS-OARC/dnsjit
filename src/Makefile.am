# Copyright (c) 2018-2019, OARC, Inc.
# All rights reserved.
#
# This file is part of dnsjit.
#
# dnsjit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# dnsjit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES =

SUBDIRS = test

AM_CFLAGS = -I$(srcdir) \
  -I$(top_srcdir) \
  $(SIMD_FLAGS) $(CPUEXT_FLAGS) \
  $(PTHREAD_CFLAGS) \
  $(luajit_CFLAGS) \
  $(libuv_CFLAGS)

EXTRA_DIST = gen-manpage.lua gen-compat.lua gen-errno.sh dnsjit.1in

BUILT_SOURCES = core/compat.hh core/log_errstr.c

bin_PROGRAMS = dnsjit

dnsjit_SOURCES = dnsjit.c globals.c contrib/trie.c
dist_dnsjit_SOURCES = core.lua lib.lua input.lua filter.lua globals.h \
  output.lua contrib/trie.h
lua_hobjects = core/compat.luaho
lua_objects = core.luao lib.luao input.luao filter.luao output.luao
dnsjit_LDADD = $(PTHREAD_LIBS) $(luajit_LIBS) $(libuv_LIBS)

# C source and headers
dnsjit_SOURCES += core/thread.c core/compat.c core/channel.c core/object/null.c core/object/icmp.c core/object/ip.c core/object/udp.c core/object/ieee802.c core/object/gre.c core/object/pcap.c core/object/dns.c core/object/linuxsll.c core/object/ether.c core/object/payload.c core/object/loop.c core/object/icmp6.c core/object/tcp.c core/object/ip6.c core/receiver.c core/producer.c core/object.c core/log.c lib/clock.c input/mmpcap.c input/zero.c input/pcap.c input/fpcap.c filter/timing.c filter/split.c filter/ipsplit.c filter/copy.c filter/layer.c output/null.c output/tlscli.c output/dnssim/tls.c output/dnssim/udp.c output/dnssim/connection.c output/dnssim/common.c output/dnssim/tcp.c output/respdiff.c output/pcap.c output/dnssim.c output/tcpcli.c output/dnscli.c output/udpcli.c
dist_dnsjit_SOURCES += core/log.h core/producer.h core/assert.h core/compat.h core/object/udp.h core/object/payload.h core/object/gre.h core/object/icmp.h core/object/ip.h core/object/pcap.h core/object/dns.h core/object/loop.h core/object/ieee802.h core/object/ether.h core/object/linuxsll.h core/object/ip6.h core/object/icmp6.h core/object/tcp.h core/object/null.h core/object.h core/receiver.h core/channel.h core/timespec.h core/thread.h lib/clock.h input/zero.h input/fpcap.h input/pcap.h input/mmpcap.h filter/copy.h filter/layer.h filter/ipsplit.h filter/split.h filter/timing.h output/dnssim.h output/dnscli.h output/dnssim/ll.h output/dnssim/internal.h output/pcap.h output/respdiff.h output/udpcli.h output/tlscli.h output/tcpcli.h output/null.h

# Lua headers
dist_dnsjit_SOURCES += core/timespec.hh core/object.hh core/channel.hh core/receiver.hh core/producer.hh core/object/icmp.hh core/object/ether.hh core/object/pcap.hh core/object/loop.hh core/object/dns.hh core/object/ip.hh core/object/null.hh core/object/icmp6.hh core/object/udp.hh core/object/ieee802.hh core/object/ip6.hh core/object/gre.hh core/object/linuxsll.hh core/object/tcp.hh core/object/payload.hh core/log.hh core/thread.hh lib/clock.hh input/mmpcap.hh input/zero.hh input/pcap.hh input/fpcap.hh filter/split.hh filter/copy.hh filter/ipsplit.hh filter/timing.hh filter/layer.hh output/udpcli.hh output/dnscli.hh output/pcap.hh output/null.hh output/respdiff.hh output/tlscli.hh output/dnssim.hh output/tcpcli.hh
lua_hobjects += core/timespec.luaho core/object.luaho core/channel.luaho core/receiver.luaho core/producer.luaho core/object/icmp.luaho core/object/ether.luaho core/object/pcap.luaho core/object/loop.luaho core/object/dns.luaho core/object/ip.luaho core/object/null.luaho core/object/icmp6.luaho core/object/udp.luaho core/object/ieee802.luaho core/object/ip6.luaho core/object/gre.luaho core/object/linuxsll.luaho core/object/tcp.luaho core/object/payload.luaho core/log.luaho core/thread.luaho lib/clock.luaho input/mmpcap.luaho input/zero.luaho input/pcap.luaho input/fpcap.luaho filter/split.luaho filter/copy.luaho filter/ipsplit.luaho filter/timing.luaho filter/layer.luaho output/udpcli.luaho output/dnscli.luaho output/pcap.luaho output/null.luaho output/respdiff.luaho output/tlscli.luaho output/dnssim.luaho output/tcpcli.luaho

# Lua sources
dist_dnsjit_SOURCES += core/producer.lua core/timespec.lua core/log.lua core/thread.lua core/compat.lua core/object/pcap.lua core/object/udp.lua core/object/ip.lua core/object/ip6.lua core/object/loop.lua core/object/ieee802.lua core/object/dns/label.lua core/object/dns/q.lua core/object/dns/rr.lua core/object/icmp.lua core/object/ether.lua core/object/null.lua core/object/payload.lua core/object/gre.lua core/object/icmp6.lua core/object/linuxsll.lua core/object/dns.lua core/object/tcp.lua core/objects.lua core/object.lua core/receiver.lua core/channel.lua lib/getopt.lua lib/clock.lua lib/parseconf.lua input/pcap.lua input/fpcap.lua input/mmpcap.lua input/zero.lua filter/split.lua filter/layer.lua filter/ipsplit.lua filter/copy.lua filter/timing.lua output/dnssim.lua output/pcap.lua output/dnscli.lua output/tlscli.lua output/udpcli.lua output/tcpcli.lua output/null.lua output/respdiff.lua
lua_objects += core/producer.luao core/timespec.luao core/log.luao core/thread.luao core/compat.luao core/object/pcap.luao core/object/udp.luao core/object/ip.luao core/object/ip6.luao core/object/loop.luao core/object/ieee802.luao core/object/dns/label.luao core/object/dns/q.luao core/object/dns/rr.luao core/object/icmp.luao core/object/ether.luao core/object/null.luao core/object/payload.luao core/object/gre.luao core/object/icmp6.luao core/object/linuxsll.luao core/object/dns.luao core/object/tcp.luao core/objects.luao core/object.luao core/receiver.luao core/channel.luao lib/getopt.luao lib/clock.luao lib/parseconf.luao input/pcap.luao input/fpcap.luao input/mmpcap.luao input/zero.luao filter/split.luao filter/layer.luao filter/ipsplit.luao filter/copy.luao filter/timing.luao output/dnssim.luao output/pcap.luao output/dnscli.luao output/tlscli.luao output/udpcli.luao output/tcpcli.luao output/null.luao output/respdiff.luao

dnsjit_LDFLAGS = -Wl,-E
dnsjit_LDADD += $(lua_hobjects) $(lua_objects)
CLEANFILES += $(lua_hobjects) $(lua_objects)

man1_MANS = dnsjit.1
CLEANFILES += $(man1_MANS)

man3_MANS = dnsjit.core.3 dnsjit.lib.3 dnsjit.input.3 dnsjit.filter.3 dnsjit.output.3
man3_MANS += dnsjit.core.producer.3 dnsjit.core.timespec.3 dnsjit.core.log.3 dnsjit.core.thread.3 dnsjit.core.compat.3 dnsjit.core.object.pcap.3 dnsjit.core.object.udp.3 dnsjit.core.object.ip.3 dnsjit.core.object.ip6.3 dnsjit.core.object.loop.3 dnsjit.core.object.ieee802.3 dnsjit.core.object.dns.label.3 dnsjit.core.object.dns.q.3 dnsjit.core.object.dns.rr.3 dnsjit.core.object.icmp.3 dnsjit.core.object.ether.3 dnsjit.core.object.null.3 dnsjit.core.object.payload.3 dnsjit.core.object.gre.3 dnsjit.core.object.icmp6.3 dnsjit.core.object.linuxsll.3 dnsjit.core.object.dns.3 dnsjit.core.object.tcp.3 dnsjit.core.objects.3 dnsjit.core.object.3 dnsjit.core.receiver.3 dnsjit.core.channel.3 dnsjit.lib.getopt.3 dnsjit.lib.clock.3 dnsjit.lib.parseconf.3 dnsjit.input.pcap.3 dnsjit.input.fpcap.3 dnsjit.input.mmpcap.3 dnsjit.input.zero.3 dnsjit.filter.split.3 dnsjit.filter.layer.3 dnsjit.filter.ipsplit.3 dnsjit.filter.copy.3 dnsjit.filter.timing.3 dnsjit.output.dnssim.3 dnsjit.output.pcap.3 dnsjit.output.dnscli.3 dnsjit.output.tlscli.3 dnsjit.output.udpcli.3 dnsjit.output.tcpcli.3 dnsjit.output.null.3 dnsjit.output.respdiff.3
CLEANFILES += *.3in $(man3_MANS)

.lua.luao:
	@mkdir -p `dirname "$@"`
	$(LUAJIT) -bg -n "dnsjit.`echo \"$@\" | sed 's%\..*%%' | sed 's%/%.%g'`" -t o "$<" "$@"

.luah.luaho:
	@mkdir -p `dirname "$@"`
	$(LUAJIT) -bg -n "dnsjit.`echo \"$@\" | sed 's%\..*%%' | sed 's%/%.%g'`_h" -t o "$<" "$@"

.hh.luah:
	@mkdir -p `dirname "$@"`
	@echo 'module(...,package.seeall);' > "$@"
	@cat "$<" | grep '^//lua:' | sed 's%^//lua:%%' >> "$@"
	@echo 'require("ffi").cdef[[' >> "$@"
	@cat "$<" | grep -v '^#' >> "$@"
	@echo ']]' >> "$@"

.1in.1:
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
  -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
  -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
  < "$<" > "$@"

.3in.3:
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
  -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
  -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
  < "$<" > "$@"

core/compat.hh: gen-compat.lua
	$(LUAJIT) "$(srcdir)/gen-compat.lua" > "$@"

core/log_errstr.c: gen-errno.sh
	"$(srcdir)/gen-errno.sh" > "$@"


dnsjit.core.3in: core.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core.lua" > "$@"

dnsjit.lib.3in: lib.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib.lua" > "$@"

dnsjit.input.3in: input.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input.lua" > "$@"

dnsjit.filter.3in: filter.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter.lua" > "$@"

dnsjit.output.3in: output.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output.lua" > "$@"

dnsjit.core.producer.3in: core/producer.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/producer.lua" > "$@"

dnsjit.core.timespec.3in: core/timespec.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/timespec.lua" > "$@"

dnsjit.core.log.3in: core/log.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/log.lua" > "$@"

dnsjit.core.thread.3in: core/thread.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/thread.lua" > "$@"

dnsjit.core.compat.3in: core/compat.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/compat.lua" > "$@"

dnsjit.core.object.pcap.3in: core/object/pcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/pcap.lua" > "$@"

dnsjit.core.object.udp.3in: core/object/udp.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/udp.lua" > "$@"

dnsjit.core.object.ip.3in: core/object/ip.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/ip.lua" > "$@"

dnsjit.core.object.ip6.3in: core/object/ip6.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/ip6.lua" > "$@"

dnsjit.core.object.loop.3in: core/object/loop.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/loop.lua" > "$@"

dnsjit.core.object.ieee802.3in: core/object/ieee802.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/ieee802.lua" > "$@"

dnsjit.core.object.dns.label.3in: core/object/dns/label.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/dns/label.lua" > "$@"

dnsjit.core.object.dns.q.3in: core/object/dns/q.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/dns/q.lua" > "$@"

dnsjit.core.object.dns.rr.3in: core/object/dns/rr.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/dns/rr.lua" > "$@"

dnsjit.core.object.icmp.3in: core/object/icmp.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/icmp.lua" > "$@"

dnsjit.core.object.ether.3in: core/object/ether.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/ether.lua" > "$@"

dnsjit.core.object.null.3in: core/object/null.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/null.lua" > "$@"

dnsjit.core.object.payload.3in: core/object/payload.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/payload.lua" > "$@"

dnsjit.core.object.gre.3in: core/object/gre.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/gre.lua" > "$@"

dnsjit.core.object.icmp6.3in: core/object/icmp6.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/icmp6.lua" > "$@"

dnsjit.core.object.linuxsll.3in: core/object/linuxsll.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/linuxsll.lua" > "$@"

dnsjit.core.object.dns.3in: core/object/dns.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/dns.lua" > "$@"

dnsjit.core.object.tcp.3in: core/object/tcp.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/tcp.lua" > "$@"

dnsjit.core.objects.3in: core/objects.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/objects.lua" > "$@"

dnsjit.core.object.3in: core/object.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object.lua" > "$@"

dnsjit.core.receiver.3in: core/receiver.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/receiver.lua" > "$@"

dnsjit.core.channel.3in: core/channel.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/channel.lua" > "$@"

dnsjit.lib.getopt.3in: lib/getopt.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib/getopt.lua" > "$@"

dnsjit.lib.clock.3in: lib/clock.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib/clock.lua" > "$@"

dnsjit.lib.parseconf.3in: lib/parseconf.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib/parseconf.lua" > "$@"

dnsjit.input.pcap.3in: input/pcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/pcap.lua" > "$@"

dnsjit.input.fpcap.3in: input/fpcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/fpcap.lua" > "$@"

dnsjit.input.mmpcap.3in: input/mmpcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/mmpcap.lua" > "$@"

dnsjit.input.zero.3in: input/zero.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/zero.lua" > "$@"

dnsjit.filter.split.3in: filter/split.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/split.lua" > "$@"

dnsjit.filter.layer.3in: filter/layer.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/layer.lua" > "$@"

dnsjit.filter.ipsplit.3in: filter/ipsplit.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/ipsplit.lua" > "$@"

dnsjit.filter.copy.3in: filter/copy.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/copy.lua" > "$@"

dnsjit.filter.timing.3in: filter/timing.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/timing.lua" > "$@"

dnsjit.output.dnssim.3in: output/dnssim.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/dnssim.lua" > "$@"

dnsjit.output.pcap.3in: output/pcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/pcap.lua" > "$@"

dnsjit.output.dnscli.3in: output/dnscli.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/dnscli.lua" > "$@"

dnsjit.output.tlscli.3in: output/tlscli.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/tlscli.lua" > "$@"

dnsjit.output.udpcli.3in: output/udpcli.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/udpcli.lua" > "$@"

dnsjit.output.tcpcli.3in: output/tcpcli.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/tcpcli.lua" > "$@"

dnsjit.output.null.3in: output/null.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/null.lua" > "$@"

dnsjit.output.respdiff.3in: output/respdiff.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/respdiff.lua" > "$@"

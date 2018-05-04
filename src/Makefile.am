# Copyright (c) 2018, OARC, Inc.
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

#SUBDIRS = test

AM_CFLAGS = -I$(srcdir) \
  -I$(top_srcdir) \
  $(PTHREAD_CFLAGS) \
  $(luajit_CFLAGS)

EXTRA_DIST = gen-manpage.lua gen-compat.lua dnsjit.1in

BUILT_SOURCES = core/compat.hh

bin_PROGRAMS = dnsjit

dnsjit_SOURCES = dnsjit.c globals.c \
  omg-dns/omg_dns.c \
  pcap-thread/pcap_thread.c \
  sllq/sllq.c
dist_dnsjit_SOURCES = core.lua lib.lua input.lua filter.lua output.lua \
  omg-dns/omg_dns.h \
  pcap-thread/pcap_thread.h \
  sllq/sllq.h
lua_hobjects = core/compat.luaho
lua_objects = core.luao lib.luao input.luao filter.luao output.luao
dnsjit_LDADD = $(PTHREAD_LIBS) $(luajit_LIBS)

# C source and headers
dnsjit_SOURCES += core/producer.c core/log.c core/receiver.c core/object.c core/object/ip.c core/object/tcp.c core/object/pcap.c core/object/dns.c core/object/icmp6.c core/object/ieee802.c core/object/udp.c core/object/loop.c core/object/packet.c core/object/ip6.c core/object/gre.c core/object/linuxsll.c core/object/icmp.c core/object/null.c core/object/ether.c core/tracking.c core/mutex.c core/compat.c lib/clock.c input/zero.c input/pcap.c input/fpcap.c input/mmpcap.c input/pcapthread.c filter/lua.c filter/split.c filter/thread.c filter/timing.c filter/coro.c filter/layer.c output/udpcli.c output/cpool.c output/tcpcli.c output/cpool/client_pool.c output/cpool/client.c output/null.c
dist_dnsjit_SOURCES += core/mutex.h core/receiver.h core/object.h core/log.h core/timespec.h core/producer.h core/tracking.h core/object/icmp.h core/object/ip.h core/object/loop.h core/object/dns.h core/object/ip6.h core/object/null.h core/object/tcp.h core/object/udp.h core/object/packet.h core/object/icmp6.h core/object/ether.h core/object/pcap.h core/object/ieee802.h core/object/linuxsll.h core/object/gre.h lib/clock.h input/zero.h input/fpcap.h input/pcap.h input/mmpcap.h input/pcapthread.h filter/lua.h filter/split.h filter/layer.h filter/timing.h filter/thread.h filter/coro.h output/null.h output/cpool/client_pool.h output/cpool/client.h output/cpool.h output/tcpcli.h output/udpcli.h

# Lua headers
dist_dnsjit_SOURCES += core/timespec.hh core/mutex.hh core/tracking.hh core/object/loop.hh core/object/gre.hh core/object/linuxsll.hh core/object/tcp.hh core/object/ether.hh core/object/icmp.hh core/object/ieee802.hh core/object/ip6.hh core/object/udp.hh core/object/packet.hh core/object/dns.hh core/object/pcap.hh core/object/icmp6.hh core/object/ip.hh core/object/null.hh core/producer.hh core/receiver.hh core/object.hh core/log.hh lib/clock.hh input/zero.hh input/mmpcap.hh input/pcap.hh input/fpcap.hh input/pcapthread.hh filter/layer.hh filter/coro.hh filter/lua.hh filter/thread.hh filter/timing.hh filter/split.hh output/udpcli.hh output/cpool.hh output/tcpcli.hh output/null.hh
lua_hobjects += core/timespec.luaho core/mutex.luaho core/tracking.luaho core/object/loop.luaho core/object/gre.luaho core/object/linuxsll.luaho core/object/tcp.luaho core/object/ether.luaho core/object/icmp.luaho core/object/ieee802.luaho core/object/ip6.luaho core/object/udp.luaho core/object/packet.luaho core/object/dns.luaho core/object/pcap.luaho core/object/icmp6.luaho core/object/ip.luaho core/object/null.luaho core/producer.luaho core/receiver.luaho core/object.luaho core/log.luaho lib/clock.luaho input/zero.luaho input/mmpcap.luaho input/pcap.luaho input/fpcap.luaho input/pcapthread.luaho filter/layer.luaho filter/coro.luaho filter/lua.luaho filter/thread.luaho filter/timing.luaho filter/split.luaho output/udpcli.luaho output/cpool.luaho output/tcpcli.luaho output/null.luaho

# Lua sources
dist_dnsjit_SOURCES += core/mutex.lua core/log.lua core/tracking.lua core/timespec.lua core/producer.lua core/object/pcap.lua core/object/icmp6.lua core/object/gre.lua core/object/ether.lua core/object/ip.lua core/object/ieee802.lua core/object/tcp.lua core/object/ip6.lua core/object/linuxsll.lua core/object/null.lua core/object/loop.lua core/object/icmp.lua core/object/packet.lua core/object/dns.lua core/object/udp.lua core/receiver.lua core/object.lua lib/getopt.lua lib/clock.lua lib/parseconf.lua input/pcapthread.lua input/fpcap.lua input/pcap.lua input/zero.lua input/mmpcap.lua filter/coro.lua filter/timing.lua filter/split.lua filter/layer.lua filter/thread.lua filter/lua.lua output/tcpcli.lua output/cpool.lua output/null.lua output/udpcli.lua
lua_objects += core/mutex.luao core/log.luao core/tracking.luao core/timespec.luao core/producer.luao core/object/pcap.luao core/object/icmp6.luao core/object/gre.luao core/object/ether.luao core/object/ip.luao core/object/ieee802.luao core/object/tcp.luao core/object/ip6.luao core/object/linuxsll.luao core/object/null.luao core/object/loop.luao core/object/icmp.luao core/object/packet.luao core/object/dns.luao core/object/udp.luao core/receiver.luao core/object.luao lib/getopt.luao lib/clock.luao lib/parseconf.luao input/pcapthread.luao input/fpcap.luao input/pcap.luao input/zero.luao input/mmpcap.luao filter/coro.luao filter/timing.luao filter/split.luao filter/layer.luao filter/thread.luao filter/lua.luao output/tcpcli.luao output/cpool.luao output/null.luao output/udpcli.luao

dnsjit_LDFLAGS = -Wl,-E
dnsjit_LDADD += $(lua_hobjects) $(lua_objects)
CLEANFILES += $(lua_hobjects) $(lua_objects)

man1_MANS = dnsjit.1
CLEANFILES += $(man1_MANS)

man3_MANS = dnsjit.core.3 dnsjit.lib.3 dnsjit.input.3 dnsjit.filter.3 dnsjit.output.3
man3_MANS += dnsjit.core.mutex.3 dnsjit.core.log.3 dnsjit.core.tracking.3 dnsjit.core.timespec.3 dnsjit.core.producer.3 dnsjit.core.object.pcap.3 dnsjit.core.object.icmp6.3 dnsjit.core.object.gre.3 dnsjit.core.object.ether.3 dnsjit.core.object.ip.3 dnsjit.core.object.ieee802.3 dnsjit.core.object.tcp.3 dnsjit.core.object.ip6.3 dnsjit.core.object.linuxsll.3 dnsjit.core.object.null.3 dnsjit.core.object.loop.3 dnsjit.core.object.icmp.3 dnsjit.core.object.packet.3 dnsjit.core.object.dns.3 dnsjit.core.object.udp.3 dnsjit.core.receiver.3 dnsjit.core.object.3 dnsjit.lib.getopt.3 dnsjit.lib.clock.3 dnsjit.lib.parseconf.3 dnsjit.input.pcapthread.3 dnsjit.input.fpcap.3 dnsjit.input.pcap.3 dnsjit.input.zero.3 dnsjit.input.mmpcap.3 dnsjit.filter.coro.3 dnsjit.filter.timing.3 dnsjit.filter.split.3 dnsjit.filter.layer.3 dnsjit.filter.thread.3 dnsjit.filter.3.3 dnsjit.output.tcpcli.3 dnsjit.output.cpool.3 dnsjit.output.null.3 dnsjit.output.udpcli.3
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

dnsjit.core.mutex.3in: core/mutex.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/mutex.lua" > "$@"

dnsjit.core.log.3in: core/log.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/log.lua" > "$@"

dnsjit.core.tracking.3in: core/tracking.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/tracking.lua" > "$@"

dnsjit.core.timespec.3in: core/timespec.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/timespec.lua" > "$@"

dnsjit.core.producer.3in: core/producer.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/producer.lua" > "$@"

dnsjit.core.object.pcap.3in: core/object/pcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/pcap.lua" > "$@"

dnsjit.core.object.icmp6.3in: core/object/icmp6.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/icmp6.lua" > "$@"

dnsjit.core.object.gre.3in: core/object/gre.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/gre.lua" > "$@"

dnsjit.core.object.ether.3in: core/object/ether.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/ether.lua" > "$@"

dnsjit.core.object.ip.3in: core/object/ip.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/ip.lua" > "$@"

dnsjit.core.object.ieee802.3in: core/object/ieee802.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/ieee802.lua" > "$@"

dnsjit.core.object.tcp.3in: core/object/tcp.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/tcp.lua" > "$@"

dnsjit.core.object.ip6.3in: core/object/ip6.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/ip6.lua" > "$@"

dnsjit.core.object.linuxsll.3in: core/object/linuxsll.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/linuxsll.lua" > "$@"

dnsjit.core.object.null.3in: core/object/null.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/null.lua" > "$@"

dnsjit.core.object.loop.3in: core/object/loop.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/loop.lua" > "$@"

dnsjit.core.object.icmp.3in: core/object/icmp.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/icmp.lua" > "$@"

dnsjit.core.object.packet.3in: core/object/packet.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/packet.lua" > "$@"

dnsjit.core.object.dns.3in: core/object/dns.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/dns.lua" > "$@"

dnsjit.core.object.udp.3in: core/object/udp.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/udp.lua" > "$@"

dnsjit.core.receiver.3in: core/receiver.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/receiver.lua" > "$@"

dnsjit.core.object.3in: core/object.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object.lua" > "$@"

dnsjit.lib.getopt.3in: lib/getopt.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib/getopt.lua" > "$@"

dnsjit.lib.clock.3in: lib/clock.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib/clock.lua" > "$@"

dnsjit.lib.parseconf.3in: lib/parseconf.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib/parseconf.lua" > "$@"

dnsjit.input.pcapthread.3in: input/pcapthread.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/pcapthread.lua" > "$@"

dnsjit.input.fpcap.3in: input/fpcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/fpcap.lua" > "$@"

dnsjit.input.pcap.3in: input/pcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/pcap.lua" > "$@"

dnsjit.input.zero.3in: input/zero.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/zero.lua" > "$@"

dnsjit.input.mmpcap.3in: input/mmpcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/mmpcap.lua" > "$@"

dnsjit.filter.coro.3in: filter/coro.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/coro.lua" > "$@"

dnsjit.filter.timing.3in: filter/timing.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/timing.lua" > "$@"

dnsjit.filter.split.3in: filter/split.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/split.lua" > "$@"

dnsjit.filter.layer.3in: filter/layer.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/layer.lua" > "$@"

dnsjit.filter.thread.3in: filter/thread.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/thread.lua" > "$@"

dnsjit.filter.3.3in: filter/lua.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/lua.lua" > "$@"

dnsjit.output.tcpcli.3in: output/tcpcli.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/tcpcli.lua" > "$@"

dnsjit.output.cpool.3in: output/cpool.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/cpool.lua" > "$@"

dnsjit.output.null.3in: output/null.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/null.lua" > "$@"

dnsjit.output.udpcli.3in: output/udpcli.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/udpcli.lua" > "$@"

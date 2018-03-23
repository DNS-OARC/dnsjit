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

EXTRA_DIST = gen-manpage.lua dnsjit.1in

bin_PROGRAMS = dnsjit

dnsjit_SOURCES = dnsjit.c \
  core/log.c core/mutex.c core/receiver.c core/tracking.c \
  core/object/dns.c core/object/packet.c \
  input/pcapthread.c input/zero.c \
  filter/lua.c filter/split.c filter/timing.c \
  output/cpool.c output/null.c \
  output/cpool/client_pool.c output/cpool/client.c \
  omg-dns/omg_dns.c \
  pcap-thread/pcap_thread.c \
  sllq/sllq.c
dist_dnsjit_SOURCES = \
  core/log.h core/mutex.h core/object.h core/receiver.h core/timespec.h core/tracking.h \
  core/object/dns.h core/object/packet.h \
  input/pcapthread.h input/zero.h \
  filter/lua.h filter/split.h filter/timing.h \
  output/cpool.h output/null.h \
  output/cpool/client_pool.h output/cpool/client.h \
  omg-dns/omg_dns.h \
  pcap-thread/pcap_thread.h \
  sllq/sllq.h
dnsjit_LDADD = $(PTHREAD_LIBS) $(luajit_LIBS)

# Lua headers
dist_dnsjit_SOURCES += \
  core/log.hh core/mutex.hh core/object.hh core/receiver.hh core/timespec.hh core/tracking.hh \
  core/object/dns.hh core/object/packet.hh \
  input/pcapthread.hh input/zero.hh \
  filter/lua.hh filter/split.hh filter/timing.hh \
  output/cpool.hh output/null.hh
lua_hobjects = \
  core/log.luaho core/mutex.luaho core/object.luaho core/receiver.luaho core/timespec.luaho core/tracking.luaho \
  core/object/dns.luaho core/object/packet.luaho \
  input/pcapthread.luaho input/zero.luaho \
  filter/lua.luaho filter/split.luaho filter/timing.luaho \
  output/cpool.luaho output/null.luaho
# Lua sources
dist_dnsjit_SOURCES += \
  core/log.lua core/mutex.lua core/object.lua core/tracking.lua \
  core/object/dns.lua core/object/packet.lua \
  lib/getopt.lua lib/parseconf.lua \
  input/pcapthread.lua input/zero.lua \
  filter/lua.lua filter/split.lua filter/timing.lua \
  output/cpool.lua output/null.lua
lua_objects = \
  core/log.luao core/mutex.luao core/object.luao core/tracking.luao \
  core/object/dns.luao core/object/packet.luao \
  lib/getopt.luao lib/parseconf.luao \
  input/pcapthread.luao input/zero.luao \
  filter/lua.luao filter/split.luao filter/timing.luao \
  output/cpool.luao output/null.luao
# Documentation only sources
dist_dnsjit_SOURCES += \
  core.lua core/receiver.lua core/timespec.lua \
  lib.lua \
  input.lua \
  filter.lua \
  output.lua
dnsjit_LDFLAGS = -Wl,-E
dnsjit_LDADD += $(lua_hobjects) $(lua_objects)
CLEANFILES += $(lua_hobjects) $(lua_objects)

man1_MANS = dnsjit.1
CLEANFILES += $(man1_MANS)

man3_MANS = dnsjit.core.3 dnsjit.core.log.3 dnsjit.core.mutex.3 dnsjit.core.object.3 dnsjit.core.receiver.3 dnsjit.core.timespec.3 dnsjit.core.tracking.3 \
  dnsjit.core.object.dns.3 dnsjit.core.object.packet.3 \
  dnsjit.lib.3 dnsjit.lib.getopt.3 dnsjit.lib.parseconf.3 \
  dnsjit.input.3 dnsjit.input.pcapthread.3 dnsjit.input.zero.3 \
  dnsjit.filter.3 dnsjit.filter.lua.3 dnsjit.filter.split.3 dnsjit.filter.timing.3 \
  dnsjit.output.3 dnsjit.output.cpool.3 dnsjit.output.null.3
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

dnsjit.core.3in: core.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core.lua" > "$@"

dnsjit.core.log.3in: core/log.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/log.lua" > "$@"

dnsjit.core.mutex.3in: core/mutex.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/mutex.lua" > "$@"

dnsjit.core.object.3in: core/object.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object.lua" > "$@"

dnsjit.core.receiver.3in: core/receiver.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/receiver.lua" > "$@"

dnsjit.core.timespec.3in: core/timespec.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/timespec.lua" > "$@"

dnsjit.core.tracking.3in: core/tracking.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/tracking.lua" > "$@"


dnsjit.core.object.dns.3in: core/object/dns.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/dns.lua" > "$@"

dnsjit.core.object.packet.3in: core/object/packet.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/object/packet.lua" > "$@"


dnsjit.lib.3in: lib.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib.lua" > "$@"

dnsjit.lib.getopt.3in: lib/getopt.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib/getopt.lua" > "$@"

dnsjit.lib.parseconf.3in: lib/parseconf.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib/parseconf.lua" > "$@"


dnsjit.input.3in: input.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input.lua" > "$@"

dnsjit.input.pcapthread.3in: input/pcapthread.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/pcapthread.lua" > "$@"

dnsjit.input.zero.3in: input/zero.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/zero.lua" > "$@"


dnsjit.filter.3in: filter.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter.lua" > "$@"

dnsjit.filter.lua.3in: filter/lua.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/lua.lua" > "$@"

dnsjit.filter.split.3in: filter/split.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/split.lua" > "$@"

dnsjit.filter.timing.3in: filter/timing.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/timing.lua" > "$@"


dnsjit.output.3in: output.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output.lua" > "$@"

dnsjit.output.cpool.3in: output/cpool.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/cpool.lua" > "$@"

dnsjit.output.null.3in: output/null.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/null.lua" > "$@"

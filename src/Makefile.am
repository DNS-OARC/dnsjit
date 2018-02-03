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
    core/log.c core/mutex.c core/query.c core/receiver.c \
    input/pcap.c \
	filter/lua.c filter/roundrobin.c filter/thread.c filter/timing.c \
    output/cpool.c output/null.c \
    omg-dns/omg_dns.c \
    pcap-thread/pcap_thread.c \
    sllq/sllq.c \
	output/cpool/client_pool.c output/cpool/client.c
dist_dnsjit_SOURCES = \
    core/log.h core/mutex.h core/query.h core/receiver.h core/timespec.h \
    input/pcap.h \
	filter/lua.h filter/roundrobin.h filter/thread.h filter/timing.h \
    output/cpool.h output/null.h \
    omg-dns/omg_dns.h \
    pcap-thread/pcap_thread.h \
    sllq/sllq.h \
	output/cpool/client_pool.h output/cpool/client.h
dnsjit_LDADD = $(PTHREAD_LIBS) $(luajit_LIBS)

# Lua headers
dist_dnsjit_SOURCES += \
	core/log.hh core/mutex.hh core/query.hh core/receiver.hh core/timespec.hh \
    input/pcap.hh \
	filter/lua.hh filter/roundrobin.hh filter/thread.hh filter/timing.hh \
    output/cpool.hh output/null.hh
# Lua sources
dist_dnsjit_SOURCES += \
	core.lua core/chelpers.lua core/log.lua core/mutex.lua core/query.lua core/receiver.lua core/timespec.lua \
	lib.lua lib/getopt.lua \
    input.lua input/lua.lua input/pcap.lua \
	filter.lua filter/lua.lua filter/roundrobin.lua filter/thread.lua filter/timing.lua \
    output.lua output/cpool.lua output/null.lua
dnsjit_LDFLAGS = -Wl,-E
lua_objects = \
	core/chelpers.luao core/log.luao core/log.luaho core/mutex.luaho core/query.luaho core/receiver.luaho core/timespec.luaho \
	lib.luao lib/getopt.luao \
    input/pcap.luaho \
	filter/lua.luaho filter/roundrobin.luaho filter/thread.luaho filter/timing.luaho \
    output/cpool.luaho output/null.luaho \
	core/mutex.luao core/query.luao \
    input/lua.luao input/pcap.luao \
	filter/lua.luao filter/roundrobin.luao filter/thread.luao filter/timing.luao \
    output/cpool.luao output/null.luao
dnsjit_LDADD += $(lua_objects)
CLEANFILES += $(lua_objects)

man1_MANS = dnsjit.1
CLEANFILES += $(man1_MANS)

man3_MANS = dnsjit.core.3 dnsjit.core.chelpers.3 dnsjit.core.log.3 dnsjit.core.mutex.3 dnsjit.core.query.3 dnsjit.core.receiver.3 dnsjit.core.timespec.3 \
    dnsjit.lib.3 dnsjit.lib.getopt.3 \
    dnsjit.input.3 dnsjit.input.lua.3 dnsjit.input.pcap.3 \
	dnsjit.filter.3 dnsjit.filter.lua.3 dnsjit.filter.roundrobin.3 dnsjit.filter.thread.3 dnsjit.filter.timing.3 \
	dnsjit.output.3 dnsjit.output.cpool.3 dnsjit.output.null.3
CLEANFILES += *.3in $(man3_MANS)

.lua.luao:
	@mkdir -p `dirname "$@"`
	$(LUAJIT) -bg -n "dnsjit.`echo \"$@\" | sed 's%\..*%%' | sed 's%/%.%g'`" -t o "$<" "$@"

.luah.luaho:
	@mkdir -p `dirname "$@"`
	$(LUAJIT) -bg -n "dnsjit.`echo \"$@\" | sed 's%\..*%%' | sed 's%/%.%g'`_h" -t o "$<" "$@"

.hh.luah:
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

dnsjit.core.chelpers.3in: core/chelpers.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/chelpers.lua" > "$@"

dnsjit.core.log.3in: core/log.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/log.lua" > "$@"

dnsjit.core.mutex.3in: core/mutex.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/mutex.lua" > "$@"

dnsjit.core.query.3in: core/query.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/query.lua" > "$@"

dnsjit.core.receiver.3in: core/receiver.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/receiver.lua" > "$@"

dnsjit.core.timespec.3in: core/timespec.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/core/timespec.lua" > "$@"


dnsjit.lib.3in: lib.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib.lua" > "$@"

dnsjit.lib.getopt.3in: lib/getopt.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/lib/getopt.lua" > "$@"


dnsjit.input.3in: input.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input.lua" > "$@"

dnsjit.input.lua.3in: input/lua.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/lua.lua" > "$@"

dnsjit.input.pcap.3in: input/pcap.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/input/pcap.lua" > "$@"


dnsjit.filter.3in: filter.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter.lua" > "$@"

dnsjit.filter.lua.3in: filter/lua.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/lua.lua" > "$@"

dnsjit.filter.roundrobin.3in: filter/roundrobin.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/roundrobin.lua" > "$@"

dnsjit.filter.thread.3in: filter/thread.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/thread.lua" > "$@"

dnsjit.filter.timing.3in: filter/timing.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/filter/timing.lua" > "$@"


dnsjit.output.3in: output.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output.lua" > "$@"

dnsjit.output.cpool.3in: output/cpool.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/cpool.lua" > "$@"

dnsjit.output.null.3in: output/null.lua gen-manpage.lua
	$(LUAJIT) "$(srcdir)/gen-manpage.lua" "$(srcdir)/output/null.lua" > "$@"

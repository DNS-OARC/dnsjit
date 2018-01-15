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
CLEANFILES = luajit.built \
    libluajit.a libluajit.a.linked \
    luajit-cc jit luajit-cc.linked #dnsjit.1

#SUBDIRS = test

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir) \
	-I$(srcdir)/luajit/src \
    $(PTHREAD_CFLAGS)

EXTRA_DIST = luajit

bin_PROGRAMS = dnsjit

BUILT_SOURCES = luajit-cc

dnsjit_SOURCES = dnsjit.c \
    core/log.c core/mutex.c core/query.c core/receiver.c \
    input/pcap.c \
	filter/lua.c filter/roundrobin.c filter/thread.c filter/timing.c \
    output/client_pool.c output/null.c \
    omg-dns/omg_dns.c \
    pcap-thread/pcap_thread.c \
    sllq/sllq.c \
	output/client_pool/client_pool.c output/client_pool/client.c
dist_dnsjit_SOURCES = \
    core/log.h core/mutex.h core/query.h core/receiver.h core/timespec.h \
    input/pcap.h \
	filter/lua.h filter/roundrobin.h filter/thread.h filter/timing.h \
    output/client_pool.h output/null.h \
    omg-dns/omg_dns.h \
    pcap-thread/pcap_thread.h \
    sllq/sllq.h \
	output/client_pool/client_pool.h output/client_pool/client.h
dnsjit_LDADD = libluajit.a \
    $(PTHREAD_LIBS)

# Lua headers
dist_dnsjit_SOURCES += \
	core/log.hh core/mutex.hh core/query.hh core/receiver.hh core/timespec.hh \
    input/pcap.hh \
	filter/lua.hh filter/roundrobin.hh filter/thread.hh filter/timing.hh \
    output/client_pool.hh output/null.hh
# Lua sources
dist_dnsjit_SOURCES += \
	core/log.lua core/mutex.lua core/query.lua \
    input/lua.lua input/pcap.lua \
	filter/lua.lua filter/roundrobin.lua filter/thread.lua filter/timing.lua \
    output/client_pool.lua output/null.lua
dnsjit_LDFLAGS = -Wl,-E
lua_objects = \
	core/log.luao core/log.luaho core/mutex.luaho core/query.luaho core/receiver.luaho core/timespec.luaho \
    input/pcap.luaho \
	filter/lua.luaho filter/roundrobin.luaho filter/thread.luaho filter/timing.luaho \
    output/client_pool.luaho output/null.luaho \
	core/mutex.luao core/query.luao \
    input/lua.luao input/pcap.luao \
	filter/lua.luao filter/roundrobin.luao filter/thread.luao filter/timing.luao \
    output/client_pool.luao output/null.luao
dnsjit_LDADD += $(lua_objects)
CLEANFILES += $(lua_objects)

#man1_MANS = dnsjit.1

#dnsjit.1: dnsjit.1.in Makefile
#	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
#        -e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
#        -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
#        < $(srcdir)/dnsjit.1.in > dnsjit.1

luajit.built:
	$(MAKE) -C "$(srcdir)/luajit" all
	touch luajit.built

.lua.luao:
	./luajit-cc -bg -n "dnsjit.`echo \"$@\" | sed 's%\..*%%' | sed 's%/%.%g'`" -t o "$<" "$@"

.luah.luaho:
	./luajit-cc -bg -n "dnsjit.`echo \"$@\" | sed 's%\..*%%' | sed 's%/%.%g'`_h" -t o "$<" "$@"

.hh.luah:
	@echo 'module(...,package.seeall);' > "$@"
	@cat "$<" | grep '^//lua:' | sed 's%^//lua:%%' >> "$@"
	@echo 'require("ffi").cdef[[' >> "$@"
	@cat "$<" | grep -v '^#' >> "$@"
	@echo ']]' >> "$@"

luajit-cc: luajit-cc.linked

luajit-cc.linked: luajit.built
	ln -sf "$(srcdir)/luajit/src/luajit" luajit-cc
	ln -sf "$(srcdir)/luajit/src/jit" jit
	touch luajit-cc.linked

libluajit.a: libluajit.a.linked

libluajit.a.linked: luajit.built
	ln -sf "$(srcdir)/luajit/src/libluajit.a" libluajit.a
	touch libluajit.a.linked

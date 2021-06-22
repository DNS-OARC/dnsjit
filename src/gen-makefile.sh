#!/bin/sh

echo '# Copyright (c) 2018-2021, OARC, Inc.
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
CLEANFILES = *.gcda *.gcno *.gcov

SUBDIRS = test

AM_CFLAGS = -Werror=attributes \
  -I$(srcdir) \
  -I$(top_srcdir) \
  -I$(top_srcdir)/include \
  $(SIMD_FLAGS) $(CPUEXT_FLAGS) \
  $(PTHREAD_CFLAGS) \
  $(luajit_CFLAGS) \
  $(libuv_CFLAGS) \
  $(libnghttp2_CFLAGS)

EXTRA_DIST = gen-manpage.lua gen-compat.lua gen-errno.sh dnsjit.1in

BUILT_SOURCES = core/compat.hh core/log_errstr.c

bin_PROGRAMS = dnsjit

dnsjit_SOURCES = dnsjit.c globals.c
dist_dnsjit_SOURCES = core.lua lib.lua input.lua filter.lua output.lua
dnsjitincludedir = $(includedir)/dnsjit
nobase_dnsjitinclude_HEADERS = globals.h version.h
lua_hobjects = core/compat.luaho
lua_objects = core.luao lib.luao input.luao filter.luao output.luao
dnsjit_LDADD = $(PTHREAD_LIBS) $(luajit_LIBS) $(libuv_LIBS) $(libnghttp2_LIBS)

# C source and headers';

echo "dnsjit_SOURCES +=`find core lib input filter output -type f -name '*.c' | sort | while read line; do echo -n " $line"; done`"
echo "nobase_dnsjitinclude_HEADERS +=`find core lib input filter output -type f -name '*.h' | sort | while read line; do echo -n " $line"; done`"

echo '
# Lua headers'
echo "nobase_dnsjitinclude_HEADERS +=`find core lib input filter output -type f -name '*.hh' | sort | while read line; do echo -n " $line"; done`"
echo "lua_hobjects +=`find core lib input filter output -type f -name '*.hh' | sed -e 's%.hh%.luaho%g' | sort | while read line; do echo -n " $line"; done`"

echo '
# Lua sources'
echo "dist_dnsjit_SOURCES +=`find core lib input filter output -type f -name '*.lua' | sort | while read line; do echo -n " $line"; done`"
echo "lua_objects +=`find core lib input filter output -type f -name '*.lua' | sed -e 's%.lua%.luao%g' | sort | while read line; do echo -n " $line"; done`"

echo '
dnsjit_LDFLAGS = -Wl,-E
dnsjit_LDADD += $(lua_hobjects) $(lua_objects)
CLEANFILES += $(lua_hobjects) $(lua_objects)

man1_MANS = dnsjit.1
CLEANFILES += $(man1_MANS)

man3_MANS = dnsjit.core.3 dnsjit.lib.3 dnsjit.input.3 dnsjit.filter.3 dnsjit.output.3';
echo "man3_MANS +=`find core lib input filter output -type f -name '*.lua' | sed -e 's%.lua%.3%g' | sed -e 's%/%.%g' | sort | while read line; do echo -n " dnsjit.$line"; done`"

echo 'CLEANFILES += *.3in $(man3_MANS)

.lua.luao:
	@mkdir -p `dirname "$@"`
	$(LUAJIT) -bg -n "dnsjit.`echo \"$@\" | sed '"'"'s%\..*%%'"'"' | sed '"'"'s%/%.%g'"'"'`" -t o "$<" "$@"

.luah.luaho:
	@mkdir -p `dirname "$@"`
	$(LUAJIT) -bg -n "dnsjit.`echo \"$@\" | sed '"'"'s%\..*%%'"'"' | sed '"'"'s%/%.%g'"'"'`_h" -t o "$<" "$@"

.hh.luah:
	@mkdir -p `dirname "$@"`
	@echo '"'"'module(...,package.seeall);'"'"' > "$@"
	@cat "$<" | grep '"'"'^//lua:'"'"' | sed '"'"'s%^//lua:%%'"'"' >> "$@"
	@echo '"'"'require("ffi").cdef[['"'"' >> "$@"
	@cat "$<" | grep -v '"'"'^#'"'"' >> "$@"
	@echo '"'"']]'"'"' >> "$@"

.1in.1:
	sed -e '"'"'s,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'"'"' \
  -e '"'"'s,[@]PACKAGE_URL[@],$(PACKAGE_URL),g'"'"' \
  -e '"'"'s,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g'"'"' \
  < "$<" > "$@"

.3in.3:
	sed -e '"'"'s,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'"'"' \
  -e '"'"'s,[@]PACKAGE_URL[@],$(PACKAGE_URL),g'"'"' \
  -e '"'"'s,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g'"'"' \
  < "$<" > "$@"

if ENABLE_GCOV
gcov-local:
	for src in $(dnsjit_SOURCES); do \
	  gcov -x -l -r -s "$(srcdir)" "$$src"; \
	done
endif

core/compat.hh: gen-compat.lua
	$(LUAJIT) "$(srcdir)/gen-compat.lua" > "$@"

core/log_errstr.c: gen-errno.sh
	"$(srcdir)/gen-errno.sh" > "$@"
';

for file in core.lua lib.lua input.lua filter.lua output.lua; do
    man=`echo "$file"|sed -e 's%.lua%.3%g'|sed -e 's%/%.%g'`
echo "
dnsjit.${man}in: $file gen-manpage.lua
	\$(LUAJIT) \"\$(srcdir)/gen-manpage.lua\" \"\$(srcdir)/$file\" > \"\$@\"";
done

find core lib input filter output -type f -name '*.lua' | sort | while read file; do
    man=`echo "$file"|sed -e 's%.lua%.3%g'|sed -e 's%/%.%g'`
echo "
dnsjit.${man}in: $file gen-manpage.lua
	\$(LUAJIT) \"\$(srcdir)/gen-manpage.lua\" \"\$(srcdir)/$file\" > \"\$@\"";
done

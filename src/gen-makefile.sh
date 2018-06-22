#!/bin/sh

echo '# Copyright (c) 2018, OARC, Inc.
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
  $(SIMD_FLAGS) $(CPUEXT_FLAGS) \
  $(PTHREAD_CFLAGS) \
  $(luajit_CFLAGS)

EXTRA_DIST = gen-manpage.lua gen-compat.lua gen-errno.sh dnsjit.1in

BUILT_SOURCES = core/compat.hh core/log_errstr.c

bin_PROGRAMS = dnsjit

dnsjit_SOURCES = dnsjit.c globals.c
dist_dnsjit_SOURCES = core.lua lib.lua input.lua filter.lua globals.h \
  output.lua
lua_hobjects = core/compat.luaho
lua_objects = core.luao lib.luao input.luao filter.luao output.luao
dnsjit_LDADD = $(PTHREAD_LIBS) $(luajit_LIBS)

# C source and headers';

echo "dnsjit_SOURCES +=`find core lib input filter output -type f -name '*.c' -printf ' %p'`"
echo "dist_dnsjit_SOURCES +=`find core lib input filter output -type f -name '*.h' -printf ' %p'`"

echo '
# Lua headers'
echo "dist_dnsjit_SOURCES +=`find core lib input filter output -type f -name '*.hh' -printf ' %p'`"
echo "lua_hobjects +=`find core lib input filter output -type f -name '*.hh' -printf ' %p'|sed -e 's%.hh%.luaho%g'`"

echo '
# Lua sources'
echo "dist_dnsjit_SOURCES +=`find core lib input filter output -type f -name '*.lua' -printf ' %p'`"
echo "lua_objects +=`find core lib input filter output -type f -name '*.lua' -printf ' %p '|sed -e 's%.lua %.luao%g'`"

echo '
dnsjit_LDFLAGS = -Wl,-E
dnsjit_LDADD += $(lua_hobjects) $(lua_objects)
CLEANFILES += $(lua_hobjects) $(lua_objects)

man1_MANS = dnsjit.1
CLEANFILES += $(man1_MANS)

man3_MANS = dnsjit.core.3 dnsjit.lib.3 dnsjit.input.3 dnsjit.filter.3 dnsjit.output.3';
echo "man3_MANS +=`find core lib input filter output -type f -name '*.lua' -printf ' dnsjit.%p'|sed -e 's%.lua%.3%g'|sed -e 's%/%.%g'`"

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

find core lib input filter output -type f -name '*.lua' | while read file; do
    man=`echo "$file"|sed -e 's%.lua%.3%g'|sed -e 's%/%.%g'`
echo "
dnsjit.${man}in: $file gen-manpage.lua
	\$(LUAJIT) \"\$(srcdir)/gen-manpage.lua\" \"\$(srcdir)/$file\" > \"\$@\"";
done

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

AC_PREREQ(2.61)
AC_INIT([dnsjit], [0.9.0], [admin@dns-oarc.net], [dnsjit], [https://github.com/DNS-OARC/dnsjit/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/dnsjit.c])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT([disable-static])

# Checks for support.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([m], [sqrt])
AX_PTHREAD
AX_PCAP_THREAD_PCAP
AC_CHECK_LIB([ev], [ev_now], [], AC_MSG_ERROR([libev not found]))
AC_CHECK_HEADER([ev.h], [AC_CHECK_HEADERS([ev.h])], [AC_CHECK_HEADER([libev/ev.h], [AC_CHECK_HEADERS([libev/ev.h])], [AC_MSG_ERROR([libev header not found])])])
AC_SEARCH_LIBS([clock_gettime],[rt])
AC_CHECK_FUNCS([clock_nanosleep nanosleep])

# Checks for sizes
AC_CHECK_SIZEOF(void*)

# Output Makefiles
AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT

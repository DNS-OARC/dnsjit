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

AC_PREREQ(2.64)
AC_INIT([dnsjit], [0.9.3], [admin@dns-oarc.net], [dnsjit], [https://github.com/DNS-OARC/dnsjit/issues])
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

# Check --enable-warn-all
AC_ARG_ENABLE([warn-all], [AS_HELP_STRING([--enable-warn-all], [Enable all compiler warnings])], [AX_CFLAGS_WARN_ALL()])

# Check --with-extra-cflags
AC_ARG_WITH([extra-cflags], [AS_HELP_STRING([--with-extra-cflags=CFLAGS], [Add extra CFLAGS])], [
  AC_MSG_NOTICE([appending extra CFLAGS... $withval])
  AS_VAR_APPEND(CFLAGS, [" $withval"])
])

# Check --with-extra-ldflags
AC_ARG_WITH([extra-ldflags], [AS_HELP_STRING([--with-extra-ldflags=CFLAGS], [Add extra LDFLAGS])], [
  AC_MSG_NOTICE([appending extra LDFLAGS... $withval])
  AS_VAR_APPEND(LDFLAGS, [" $withval"])
])

# Checks for support.
AX_EXT
AC_HEADER_TIME
AX_PTHREAD
AX_PCAP_THREAD_PCAP
AC_CHECK_LIB([ev], [ev_now], [], AC_MSG_ERROR([libev not found]))
AC_CHECK_HEADER([ev.h], [AC_CHECK_HEADERS([ev.h])], [AC_CHECK_HEADER([libev/ev.h], [AC_CHECK_HEADERS([libev/ev.h])], [AC_MSG_ERROR([libev header not found])])])
AC_CHECK_HEADERS([net/ethernet.h])
AC_CHECK_HEADERS([net/ethertypes.h])
AC_SEARCH_LIBS([clock_gettime],[rt])
AC_CHECK_FUNCS([clock_nanosleep nanosleep])
PKG_CHECK_MODULES([luajit], [luajit >= 2],,AC_MSG_ERROR([luajit v2+ not found]))
AC_PATH_PROGS([LUAJIT], [luajit luajit51])
if test "x$ac_cv_path_LUAJIT" = "x"; then
  AC_MSG_ERROR([luajit not found])
fi
AC_CHECK_HEADERS([lmdb.h])
AC_CHECK_LIB([lmdb], [mdb_env_create])
AC_CHECK_HEADERS([ck_ring.h],,[
  AC_CHECK_HEADERS([ck/ck_ring.h],,[
    ac_cv_header_ck_ring_h=; unset ac_cv_header_ck_ring_h
    AS_VAR_APPEND(CFLAGS, [" -I/usr/include/ck"])
    AC_CHECK_HEADERS([ck_ring.h])
  ])
])
AC_CHECK_LIB([ck], [ck_array_init])

# Checks for sizes
AC_CHECK_SIZEOF([void*])
AC_CHECK_SIZEOF([pthread_t],,[#include <pthread.h>])
AC_CHECK_SIZEOF([pthread_mutex_t],,[#include <pthread.h>])
AC_CHECK_SIZEOF([pthread_cond_t],,[#include <pthread.h>])
AC_CHECK_SIZEOF([struct sockaddr_storage],,[#include <sys/types.h>
#include <sys/socket.h>])

# Output Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  examples/Makefile
])
AC_OUTPUT

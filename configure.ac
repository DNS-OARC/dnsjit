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

AC_PREREQ(2.64)
AC_INIT([dnsjit], [0.9.8], [admin@dns-oarc.net], [dnsjit], [https://github.com/DNS-OARC/dnsjit/issues])
AC_DEFINE([PACKAGE_MAJOR_VERSION], [0], [Define to the major version of this package.])
AC_DEFINE([PACKAGE_MINOR_VERSION], [9], [Define to the minor version of this package.])
AC_DEFINE([PACKAGE_PATCH_VERSION], [8], [Define to the patch version of this package.])
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
AC_CHECK_LIB([pcap], [pcap_open_live], [], [AC_MSG_ERROR([libpcap not found])])
AC_CHECK_HEADER([pcap/pcap.h], [], [AC_MSG_ERROR([libpcap header not found])])
AC_CHECK_HEADERS([endian.h sys/endian.h machine/endian.h sys/time.h byteswap.h])
AC_CHECK_FUNCS([pcap_create pcap_set_tstamp_precision pcap_set_immediate_mode])
AC_CHECK_FUNCS([pcap_set_tstamp_type pcap_setdirection sched_yield])
AC_CHECK_FUNCS([pcap_open_offline_with_tstamp_precision pcap_activate])
AC_CHECK_TYPES([pcap_direction_t], [], [], [[#include <pcap/pcap.h>]])
AC_CHECK_HEADERS([net/ethernet.h])
AC_CHECK_HEADERS([net/ethertypes.h])
AC_SEARCH_LIBS([clock_gettime],[rt])
AC_CHECK_FUNCS([clock_nanosleep nanosleep])
PKG_CHECK_MODULES([luajit], [luajit >= 2],, [AC_MSG_ERROR([luajit v2+ not found])])
AC_PATH_PROGS([LUAJIT], [luajit luajit51])
if test "x$ac_cv_path_LUAJIT" = "x"; then
  AC_MSG_ERROR([luajit not found])
fi
AC_CHECK_HEADERS([lmdb.h])
AC_CHECK_LIB([lmdb], [mdb_env_create])
PKG_CHECK_MODULES([ck], [ck >= 0], [
  AS_VAR_APPEND([CFLAGS], [" $ck_CFLAGS"])
  AS_VAR_APPEND([LIBS], [" $ck_LIBS"])
], [
  AC_CHECK_HEADERS([ck_ring.h ck_pr.h],, [AC_MSG_ERROR([libck headers not found])])
  AC_CHECK_LIB([ck], [ck_array_init],, [AC_MSG_ERROR([libck not found])])
])
AC_CHECK_LIB([gnutls], [gnutls_init],, [AC_MSG_ERROR([libgnutls not found])])

# Checks for sizes
AC_CHECK_SIZEOF([void*])
AC_CHECK_SIZEOF([pthread_t],,[#include <pthread.h>])
AC_CHECK_SIZEOF([pthread_mutex_t],,[#include <pthread.h>])
AC_CHECK_SIZEOF([pthread_cond_t],,[#include <pthread.h>])
AC_CHECK_SIZEOF([struct sockaddr_storage],,[#include <sys/types.h>
#include <sys/socket.h>])
AC_CHECK_SIZEOF([ck_ring_t],,[#if defined(__GNUC__) || defined(__SUNPRO_C)
#include "gcc/ck_cc.h"
#ifdef CK_CC_RESTRICT
#undef CK_CC_RESTRICT
#define CK_CC_RESTRICT __restrict__
#endif
#endif
#include <ck_ring.h>])
AC_CHECK_SIZEOF([ck_ring_buffer_t],,[#if defined(__GNUC__) || defined(__SUNPRO_C)
#include "gcc/ck_cc.h"
#ifdef CK_CC_RESTRICT
#undef CK_CC_RESTRICT
#define CK_CC_RESTRICT __restrict__
#endif
#endif
#include <ck_ring.h>])
AC_CHECK_SIZEOF([gnutls_session_t],,[#include <gnutls/gnutls.h>])
AC_CHECK_SIZEOF([gnutls_certificate_credentials_t],,[#include <gnutls/gnutls.h>])
AC_CHECK_SIZEOF([struct pollfd],,[#include <poll.h>])

# Output Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/test/Makefile
  examples/Makefile
])
AC_OUTPUT

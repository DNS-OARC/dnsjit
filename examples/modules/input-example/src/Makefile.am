MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES =

AM_CFLAGS = -Werror=attributes \
  -I$(srcdir) \
  -I$(top_srcdir)

pkglibdir = $(libdir)/lua/5.1/$(PACKAGE)
pkglib_LTLIBRARIES = zero.la
zero_la_SOURCES = input/zero.c
zero_la_LDFLAGS = -Wl,-E -module -avoid-version -shared

zerolibdir = $(datadir)/lua/5.1/example/input
dist_zerolib_DATA = input/zero.lua

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES =

AM_CFLAGS = -Werror=attributes \
  -I$(srcdir) \
  -I$(top_srcdir)

pkglibdir = $(libdir)/lua/5.1/$(PACKAGE)
pkglib_LTLIBRARIES = null.la
null_la_SOURCES = output/null.c
null_la_LDFLAGS = -Wl,-E -module -avoid-version -shared

nulllibdir = $(datadir)/lua/5.1/example/output
dist_nulllib_DATA = output/null.lua

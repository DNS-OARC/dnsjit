MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES =

AM_CFLAGS = -Werror=attributes \
  -I$(srcdir) \
  -I$(top_srcdir)

pkglibdir = $(libdir)/lua/5.1/$(PACKAGE)
pkglib_LTLIBRARIES = counter.la
counter_la_SOURCES = filter/counter.c
counter_la_LDFLAGS = -Wl,-E -module -avoid-version -shared

counterlibdir = $(datadir)/lua/5.1/example/filter
dist_counterlib_DATA = filter/counter.lua

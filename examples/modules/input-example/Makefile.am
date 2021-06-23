MAINTAINERCLEANFILES = $(srcdir)/Makefile.in \
  $(srcdir)/configure

SUBDIRS = src

dist_doc_DATA = README.md

EXTRA_DIST = test.lua

test:
	dnsjit $(srcdir)/test.lua

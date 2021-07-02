MAINTAINERCLEANFILES = $(srcdir)/Makefile.in \
  $(srcdir)/configure

SUBDIRS = src

dist_doc_DATA = README.md

EXTRA_DIST = dnsjit_version.lua test.lua

test:
	LUA_CPATH="@DNSJIT_ROOT@/lib/lua/5.1/?.so;;" LUA_PATH="@DNSJIT_ROOT@/share/lua/5.1/?.lua;;" $(DNSJIT) $(srcdir)/test.lua

# Copyright (c) 2018-2021, OARC, Inc.
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
CLEANFILES = test*.log test*.trs test*.out \
  *.pcap-dist

TESTS = test1.sh test2.sh test3.sh test4.sh test5.sh test6.sh test-ipsplit.sh \
  test-trie.sh test-base64url.sh

test1.sh: dns.pcap-dist

test2.sh: dns.pcap-dist

test3.sh: dns.pcap-dist

test4.sh: dns.pcap-dist

test5.sh: dns.pcap-dist

test6.sh: dns.pcap-dist

test-ipsplit.sh: pellets.pcap-dist dns.pcap-dist

test-trie.sh: pellets.pcap-dist dns.pcap-dist

.pcap.pcap-dist:
	cp "$<" "$@"

EXTRA_DIST = $(TESTS) \
  dns.pcap pellets.pcap test_ipsplit.lua test_trie.lua test_base64url.lua \
  test1.gold test2.gold test3.gold test4.gold

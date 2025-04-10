# Copyright (c) 2018-2024 OARC, Inc.
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
  *.pcap-dist *.lz4-dist *.zst-dist

TESTS = test1.sh test2.sh test3.sh test4.sh test6.sh test-ipsplit.sh \
  test-trie.sh test-base64url.sh test-padding.sh test-sll2.sh

test1.sh: dns.pcap-dist dns.pcap.lz4-dist dns.pcap.zst-dist \
  dns.pcap.xz-dist dns.pcap.gz-dist

test2.sh: dns.pcap-dist

test3.sh: dns.pcap-dist

test4.sh: dns.pcap-dist

test6.sh: dns.pcap-dist

test-ipsplit.sh: pellets.pcap-dist dns.pcap-dist

test-trie.sh: pellets.pcap-dist dns.pcap-dist

test-padding.sh: 46vs45.pcap-dist tcp-response-with-trailing-junk.pcap-dist \
  ip6-udp-padd.pcap-dist ip6-tcp-padd.pcap-dist

test-sll2.sh: sll2.pcap-dist

.pcap.pcap-dist:
	cp "$<" "$@"

.lz4.lz4-dist:
	cp "$<" "$@"

.zst.zst-dist:
	cp "$<" "$@"

.xz.xz-dist:
	cp "$<" "$@"

.gz.gz-dist:
	cp "$<" "$@"

EXTRA_DIST = $(TESTS) \
  dns.pcap pellets.pcap test_ipsplit.lua test_trie.lua test_base64url.lua \
  test1.gold test2.gold test3.gold test4.gold test_compressupport.lua \
  dns.pcap.lz4 dns.pcap.zst dns.pcap.xz dns.pcap.gz \
  46vs45.pcap tcp-response-with-trailing-junk.pcap test_padding.gold \
  test_padding.lua ip6-udp-padd.pcap ip6-tcp-padd.pcap \
  test-sll2.gold sll2.pcap

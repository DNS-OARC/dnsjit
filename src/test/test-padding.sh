#!/bin/sh -ex
# Copyright (c) 2025 OARC, Inc.
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

../dnsjit "$srcdir/test_padding.lua" -r 46vs45.pcap-dist >test_padding.out
../dnsjit "$srcdir/test_padding.lua" -r tcp-response-with-trailing-junk.pcap-dist >>test_padding.out
../dnsjit "$srcdir/test_padding.lua" -r ip6-udp-padd.pcap-dist >>test_padding.out
../dnsjit "$srcdir/test_padding.lua" -r ip6-tcp-padd.pcap-dist >>test_padding.out
diff "$srcdir/test_padding.gold" test_padding.out

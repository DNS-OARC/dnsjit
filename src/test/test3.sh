#!/bin/sh -e
# Copyright (c) 2018-2025 OARC, Inc.
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

../dnsjit "$srcdir/../../examples/filter_rcode.lua" dns.pcap-dist 0 >test3.out
../dnsjit "$srcdir/../../examples/filter_rcode.lua" dns.pcap-dist 1 >>test3.out
diff "$srcdir/test3.gold" test3.out

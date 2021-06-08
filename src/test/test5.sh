#!/bin/sh -e
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

# TODO: install input-example?
# ../dnsjit "$srcdir/../../examples/test_throughput.lua" -vvvvv -t -s 1000000
../dnsjit "$srcdir/../../examples/test_pcap_read.lua" -vvvvv dns.pcap-dist
../dnsjit "$srcdir/../../examples/test_pcap_read.lua" -l -vvvvv dns.pcap-dist
../dnsjit "$srcdir/../../examples/test_pcap_read.lua" -p -vvvvv dns.pcap-dist
../dnsjit "$srcdir/../../examples/test_pcap_read.lua" -l -p -vvvvv dns.pcap-dist

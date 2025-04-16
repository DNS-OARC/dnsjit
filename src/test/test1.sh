#!/bin/sh -ex
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

../dnsjit "$srcdir/../../examples/dumpdns.lua" dns.pcap-dist >test1.out
diff "$srcdir/test1.gold" test1.out

support=`../dnsjit "$srcdir/test_compressupport.lua"`
if echo "$support"|grep -q lz4; then
    ../dnsjit "$srcdir/../../examples/dumpdns.lua" dns.pcap.lz4-dist lz4 >test1.out
    diff "$srcdir/test1.gold" test1.out
fi
if echo "$support"|grep -q zstd; then
    ../dnsjit "$srcdir/../../examples/dumpdns.lua" dns.pcap.zst-dist zstd >test1.out
    diff "$srcdir/test1.gold" test1.out
fi
if echo "$support"|grep -q lzma; then
    ../dnsjit "$srcdir/../../examples/dumpdns.lua" dns.pcap.xz-dist xz >test1.out
    diff "$srcdir/test1.gold" test1.out
fi
if echo "$support"|grep -q gzip; then
    ../dnsjit "$srcdir/../../examples/dumpdns.lua" dns.pcap.gz-dist gz >test1.out
    diff "$srcdir/test1.gold" test1.out
fi

if echo "$support"|grep -q lz4; then
    ../dnsjit "$srcdir/../../examples/dumpdns.lua" dns.pcap.lz4-dist lz4 mmap >test1.out
    diff "$srcdir/test1.gold" test1.out
fi
if echo "$support"|grep -q zstd; then
    ../dnsjit "$srcdir/../../examples/dumpdns.lua" dns.pcap.zst-dist zstd mmap >test1.out
    diff "$srcdir/test1.gold" test1.out
fi
if echo "$support"|grep -q lzma; then
    ../dnsjit "$srcdir/../../examples/dumpdns.lua" dns.pcap.xz-dist xz mmap >test1.out
    diff "$srcdir/test1.gold" test1.out
fi
if echo "$support"|grep -q gzip; then
    ../dnsjit "$srcdir/../../examples/dumpdns.lua" dns.pcap.gz-dist gz mmap >test1.out
    diff "$srcdir/test1.gold" test1.out
fi

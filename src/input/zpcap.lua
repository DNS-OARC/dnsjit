-- Copyright (c) 2018-2025 OARC, Inc.
-- All rights reserved.
--
-- This file is part of dnsjit.
--
-- dnsjit is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- dnsjit is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.

-- dnsjit.input.zpcap
-- Read input from a PCAP file that is compressed
--   local input = require("dnsjit.input.zpcap").new()
--   input:zstd()
--   input:open("file.pcap.zst")
--   input:receiver(filter_or_output)
--   input:run()
--
-- Read input from a PCAP file that is compressed and parse the PCAP without
-- libpcap.
-- After opening a file and reading the PCAP header, the attributes are
-- populated.
-- .SS Attributes
-- .TP
-- is_swapped
-- Indicate if the byte order in the PCAP is in reverse order of the host.
-- .TP
-- is_nanosec
-- Indicate if the time stamps are in nanoseconds or not.
-- .TP
-- magic_number
-- Magic number.
-- .TP
-- version_major
-- Major version number.
-- .TP
-- version_minor
-- Minor version number.
-- .TP
-- thiszone
-- GMT to local correction.
-- .TP
-- sigfigs
-- Accuracy of timestamps.
-- .TP
-- snaplen
-- Max length of captured packets, in octets.
-- .TP
-- network
-- The link type found in the PCAP header, see https://www.tcpdump.org/linktypes.html .
-- .TP
-- linktype
-- The data link type, mapped from
-- .IR network .
module(...,package.seeall)

require("dnsjit.input.zpcap_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "input_zpcap_t"
local input_zpcap_t = ffi.typeof(t_name)
local Zpcap = {}

-- Create a new Zpcap input.
function Zpcap.new()
    local self = {
        _receiver = nil,
        obj = input_zpcap_t(),
    }
    C.input_zpcap_init(self.obj)
    ffi.gc(self.obj, C.input_zpcap_destroy)
    return setmetatable(self, { __index = Zpcap })
end

-- Return the Log object to control logging of this instance or module.
function Zpcap:log()
    if self == nil then
        return C.input_zpcap_log()
    end
    return self.obj._log
end

-- Set the receiver to pass objects to.
function Zpcap:receiver(o)
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

-- Return the C functions and context for producing objects.
function Zpcap:produce()
    return C.input_zpcap_producer(self.obj), self.obj
end

-- Use
-- .B posix_fadvise()
-- to indicate sequential reading (if supported), may increase performance.
-- MUST be called before
-- .BR open() .
function Zpcap:fadvise_sequential()
    self.obj.use_fadvise = 1
end

-- Use liblz4 to decompress the input file/data.
function Zpcap:lz4()
    self.obj.compression = "input_zpcap_type_lz4"
end

-- Use libzstd to decompress the input file/data.
function Zpcap:zstd()
    self.obj.compression = "input_zpcap_type_zstd"
end

-- Use zlib/gzip to decompress the input file/data.
function Zpcap:gzip()
    self.obj.compression = "input_zpcap_type_gzip"
end

-- Use liblzma/xz to decompress the input file/data.
function Zpcap:lzma()
    self.obj.compression = "input_zpcap_type_lzma"
end

-- Return true if support for selected compression library is built in.
function Zpcap:have_support()
    if C.input_zpcap_have_support(self.obj) == 1 then
        return true
    end
    return false
end

-- Open a PCAP file for processing and read the PCAP header.
-- Returns 0 on success.
function Zpcap:open(file)
    return C.input_zpcap_open(self.obj, file)
end

-- Open a PCAP file for processing and read the PCAP header using a
-- file descriptor, for example
-- .B io.stdin
-- or with
-- .BR io.open() .
-- Will not take ownership of the file descriptor.
-- Returns 0 on success.
function Zpcap:openfp(fp)
    return C.input_zpcap_openfp(self.obj, fp)
end

-- Start processing packets and send each packet read to the receiver.
-- Returns 0 if all packets was read successfully.
function Zpcap:run()
    return C.input_zpcap_run(self.obj)
end

-- Return the number of packets seen.
function Zpcap:packets()
    return tonumber(self.obj.pkts)
end

-- dnsjit.input.fpcap (3)
return Zpcap

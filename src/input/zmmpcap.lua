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

-- dnsjit.input.zmmpcap
-- Read input from a PCAP file using mmap()
--   local input = require("dnsjit.input.zmmpcap").new()
--   input:zstd()
--   input:open("file.pcap.zst")
--   input:receiver(filter_or_output)
--   input:run()
--
-- Read input from a PCAP file by mapping the whole file to memory using
-- .B mmap()
-- and parse the PCAP without libpcap.
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

require("dnsjit.input.zmmpcap_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "input_zmmpcap_t"
local input_zmmpcap_t = ffi.typeof(t_name)
local Zmmpcap = {}

-- Create a new Zmmpcap input.
function Zmmpcap.new()
    local self = {
        _receiver = nil,
        obj = input_zmmpcap_t(),
    }
    C.input_zmmpcap_init(self.obj)
    ffi.gc(self.obj, C.input_zmmpcap_destroy)
    return setmetatable(self, { __index = Zmmpcap })
end

-- Return the Log object to control logging of this instance or module.
function Zmmpcap:log()
    if self == nil then
        return C.input_zmmpcap_log()
    end
    return self.obj._log
end

-- Set the receiver to pass objects to.
function Zmmpcap:receiver(o)
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

-- Return the C functions and context for producing objects.
function Zmmpcap:produce()
    return C.input_zmmpcap_producer(self.obj), self.obj
end

-- Use liblz4 to decompress the input file/data.
function Zmmpcap:lz4()
    self.obj.compression = "input_zmmpcap_type_lz4"
end

-- Use libzstd to decompress the input file/data.
function Zmmpcap:zstd()
    self.obj.compression = "input_zmmpcap_type_zstd"
end

-- Use zlib/gzip to decompress the input file/data.
function Zmmpcap:gzip()
    self.obj.compression = "input_zmmpcap_type_gzip"
end

-- Use liblzma/xz to decompress the input file/data.
function Zmmpcap:lzma()
    self.obj.compression = "input_zmmpcap_type_lzma"
end

-- Return true if support for selected compression library is built in.
function Zmmpcap:have_support()
    if C.input_zmmpcap_have_support(self.obj) == 1 then
        return true
    end
    return false
end

-- Open a PCAP file for processing and read the PCAP header.
-- Returns 0 on success.
function Zmmpcap:open(file)
    return C.input_zmmpcap_open(self.obj, file)
end

-- Start processing packets and send each packet read to the receiver.
-- Returns 0 if all packets was read successfully.
function Zmmpcap:run()
    return C.input_zmmpcap_run(self.obj)
end

-- Return the number of packets seen.
function Zmmpcap:packets()
    return tonumber(self.obj.pkts)
end

return Zmmpcap

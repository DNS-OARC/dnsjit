-- Copyright (c) 2018-2021, OARC, Inc.
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

-- dnsjit.output.pcap
-- Output to a PCAP using libpcap
--   local output = require("dnsjit.output.pcap").new()
--   output:open("file.pcap")
--   ...
--   output:close()
--
-- Output module for writing
-- .I dnsjit.core.object.pcap
-- objects to a PCAP,
module(...,package.seeall)

require("dnsjit.output.pcap_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_pcap_t"
local output_pcap_t = ffi.typeof(t_name)
local Pcap = {}

-- Create a new Pcap output.
function Pcap.new()
    local self = {
        obj = output_pcap_t(),
    }
    C.output_pcap_init(self.obj)
    ffi.gc(self.obj, C.output_pcap_destroy)
    return setmetatable(self, { __index = Pcap })
end

-- Return the Log object to control logging of this instance or module.
function Pcap:log()
    if self == nil then
        return C.output_pcap_log()
    end
    return self.obj._log
end

-- Open the PCAP
-- .I file
-- to write to using the
-- .I linktype
-- and
-- .IR snaplen .
-- Returns 0 on success.
function Pcap:open(file, linktype, snaplen)
    return C.output_pcap_open(self.obj, file, linktype, snaplen)
end

-- Close the PCAP.
function Pcap:close()
    C.output_pcap_close(self.obj)
end

-- Return the C functions and context for receiving objects.
function Pcap:receive()
    return C.output_pcap_receiver(self.obj), self.obj
end

-- dnsjit.input.pcap (3)
return Pcap

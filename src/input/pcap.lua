-- Copyright (c) 2018-2024 OARC, Inc.
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

-- dnsjit.input.pcap
-- Read input from an interface or PCAP file using libpcap
--   local input = require("dnsjit.input.pcap").new()
--   input:open_offline("file.pcap")
--   input:receiver(filter_or_output)
--   input:run()
--
-- Input module for reading packets from interfaces and PCAP files.
module(...,package.seeall)

require("dnsjit.input.pcap_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "input_pcap_t"
local input_pcap_t = ffi.typeof(t_name)
local Pcap = {}

-- Create a new Pcap input.
function Pcap.new()
    local self = {
        _receiver = nil,
        obj = input_pcap_t(),
    }
    C.input_pcap_init(self.obj)
    ffi.gc(self.obj, C.input_pcap_destroy)
    return setmetatable(self, { __index = Pcap })
end

-- Return the Log object to control logging of this instance or module.
function Pcap:log()
    if self == nil then
        return C.input_pcap_log()
    end
    return self.obj._log
end

-- Set the receiver to pass objects to.
function Pcap:receiver(o)
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

-- Return the C functions and context for producing objects.
function Pcap:produce()
    return C.input_pcap_producer(self.obj), self.obj
end

-- Open a live packet capture on
-- .IR source ,
-- which is an interface name or "any" (Linux) / "all" (BSD).
-- Must be activated before use.
function Pcap:create(source)
    return C.input_pcap_create(self.obj, source)
end

-- Activate a live packet capture, see
-- .BR pcap_activate (3pcap)
-- for more information and possible return values.
function Pcap:activate()
    return C.input_pcap_activate(self.obj)
end

-- Open a PCAP file for processing, see
-- .BR pcap_open_offline (3pcap)
-- for more information.
-- Returns 0 on success.
function Pcap:open_offline(file)
    return C.input_pcap_open_offline(self.obj, file)
end

-- Process packets from a live capture or savefile until
-- .I cnt
-- packets are processed, see
-- .BR pcap_loop (3pcap)
-- for more information and possible return values.
function Pcap:loop(cnt)
    if cnt == nil then
        cnt = -1
    end
    return C.input_pcap_loop(self.obj, cnt)
end

-- Process packets from a live capture or savefile until
-- .I cnt
-- packets are processed, see
-- .BR pcap_dispatch (3pcap)
-- for more information and possible return values.
function Pcap:dispatch(cnt)
    if cnt == nil then
        cnt = -1
    end
    return C.input_pcap_dispatch(self.obj, cnt)
end

-- Return the number of packets seen.
function Pcap:packets()
    return tonumber(self.obj.pkts)
end

-- Return the linktype of the opened PCAP.
function Pcap:linktype()
    return self.obj.linktype
end

-- Return the snaplen of the opened PCAP.
function Pcap:snaplen()
    return self.obj.snaplen
end

-- dnsjit.output.pcap (3)
return Pcap

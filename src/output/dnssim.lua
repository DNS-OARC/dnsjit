-- Copyright (c) 2018-2019, CZ.NIC, z.s.p.o.
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

-- dnsjit.output.dnssim
-- Simulate independent DNS clients over various transports
--   TODO
--
-- Output module for simulating traffic from huge number of independent,
-- individual DNS clients. Uses libuv for asynchronous communication.
module(...,package.seeall)

require("dnsjit.output.dnssim_h")
local ffi = require("ffi")
local C = ffi.C

local DnsSim = {}

-- Create a new DnsSim output for up to max_clients.
function DnsSim.new(max_clients)
    local self = {
        obj = C.output_dnssim_new(max_clients),
    }
    ffi.gc(self.obj, C.output_dnssim_free)
    return setmetatable(self, { __index = DnsSim })
end

-- Return the Log object to control logging of this instance or module.
function DnsSim:log()
    if self == nil then
        return C.output_dnssim_log()
    end
    return self.obj._log
end

-- Set the transport to UDP (without any TCP fallback).
function DnsSim:udp_only()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY)
end

-- Set the preferred transport to UDP. This transport falls back to TCP
-- for individual queries if TC bit is set in received answer.
function DnsSim:udp()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_UDP)
    self.obj.transport = "OUTPUT_DNSSIM_TRANSPORT_UDP"
end

-- Set the transport to TCP.
function DnsSim:tcp()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_TCP)
    self.obj.transport = "OUTPUT_DNSSIM_TRANSPORT_TCP"
end

-- Set the transport to TLS.
function DnsSim:tls()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_TLS)
end

-- Return the C function and context for receiving objects.
function DnsSim:receive()
    return C.output_dnssim_receiver(), self.obj
end

-- Run the libuv loop once without blocking when there is no I/O. This
-- should be called repeatedly until 0 is returned and no more data
-- is expected to be received by DnsSim.
function DnsSim:run_nowait()
    return C.output_dnssim_run_nowait(self.obj)
end

return DnsSim

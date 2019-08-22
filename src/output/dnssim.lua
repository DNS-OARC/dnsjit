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
-- Simulate independent UDP/TCP DNS clients
--   TODO
--
-- Output module for simulating traffic from huge number of independent,
-- individual DNS clients using UDP and/or TCP.
module(...,package.seeall)

require("dnsjit.output.dnssim_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_dnssim_t"
local output_dnssim_t = ffi.typeof(t_name)
local DnsSim = {}

-- Create a new DnsSim output.
function DnsSim.new()
    local self = {
        obj = output_dnssim_t(),
    }
    C.output_dnssim_init(self.obj)
    ffi.gc(self.obj, C.output_dnssim_destroy)
    return setmetatable(self, { __index = DnsSim })
end

-- Return the Log object to control logging of this instance or module.
function DnsSim:log()
    if self == nil then
        return C.output_dnssim_log()
    end
    return self.obj._log
end

-- Return the C function and context for receiving objects.
function DnsSim:receive()
    return C.output_dnssim_receiver(), self.obj
end

return DnsSim

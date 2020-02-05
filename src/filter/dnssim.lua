-- Copyright (c) 2019 CZ.NIC, z.s.p.o.
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

-- dnsjit.filter.dnssim
-- Prepare packets for dnssim output layer and optionally split them
-- among multiple receivers in a client-aware (source IP) manner.
--   local filter = require("dnsjit.filter.dnssim").new()
--   filter.receiver(...)
--   filter.receiver(...)
--   filter.receiver(...)
--   input.receiver(filter)
--
-- Filter for preparing packets for dnssim output component.
module(...,package.seeall)

require("dnsjit.filter.dnssim_h")
local bit = require("bit")
local object = require("dnsjit.core.objects")
local ffi = require("ffi")
local C = ffi.C

local DnsSim = {}

-- Create a new DnsSim filter.
function DnsSim.new()
    local self = {
        --receivers = {},
        obj = C.filter_dnssim_new(),
        --clients = {},
        --i_receiver = 1,
    }
    ffi.gc(self.obj, C.filter_dnssim_free)
    return setmetatable(self, { __index = DnsSim })
end

-- Return the Log object to control logging of this instance or module.
function DnsSim:log()
    if self == nil then
        return C.filter_dnssim_log()
    end
    return self.obj._log
end

-- Return the C functions and context for receiving objects.
function DnsSim:receive()
    local recv = C.filter_dnssim_receiver(self.obj)
    return recv, self.obj
end

-- Set the receiver to pass objects to, this can be called multiple times to
-- set addtional receivers.
function DnsSim:receiver(o)
    local recv, ctx = o:receive()
    C.filter_dnssim_add(self.obj, recv, ctx)
end

return DnsSim

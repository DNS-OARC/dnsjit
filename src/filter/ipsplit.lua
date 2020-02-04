-- Copyright (c) 2019-2020 CZ.NIC, z.s.p.o.
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

-- dnsjit.filter.ipsplit
-- Pass packets to receivers in various ways. Filter is aware of source
-- IP/IPv6 address and always assigns packets from given source address
-- to the same receiver.
--   local ipsplit = require("dnsjit.filter.ipsplit").new()
--   ipsplit.receiver(...)
--   ipsplit.receiver(...)
--   ipsplit.receiver(...)
--   input.receiver(ipsplit)
--
-- Filter to pass objects based on source IP to other receivers.
module(...,package.seeall)

require("dnsjit.filter.ipsplit_h")
local bit = require("bit")
local object = require("dnsjit.core.objects")
local ffi = require("ffi")
local C = ffi.C

local IpSplit = {}

-- Create a new IpSplit filter.
function IpSplit.new()
    local self = {
        obj = C.filter_ipsplit_new(),
    }
    ffi.gc(self.obj, C.filter_ipsplit_free)
    return setmetatable(self, { __index = IpSplit })
end

-- Return the Log object to control logging of this instance or module.
function IpSplit:log()
    if self == nil then
        return C.filter_ipsplit_log()
    end
    return self.obj._log
end

-- Return the C functions and context for receiving objects.
function IpSplit:receive()
    local recv = C.filter_ipsplit_receiver(self.obj)
    return recv, self.obj
end

-- Set the receiver to pass objects to, this can be called multiple times to
-- set addtional receivers. The weight parameter can be used to adjust
-- distribution of clients among receivers. Weight must be a positive integer
-- (default is 1).
function IpSplit:receiver(o, weight)
    local recv, ctx = o:receive()
    if weight == nil then
        weight = 1
    end
    C.filter_ipsplit_add(self.obj, recv, ctx, weight)
end

-- Number of input packets discarded due to various reasons.
-- To investigate causes, run with increased logging level.
function IpSplit:discarded()
    return tonumber(self.obj.discarded)
end

return IpSplit

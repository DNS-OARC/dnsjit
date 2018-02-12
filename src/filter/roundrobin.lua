-- Copyright (c) 2018, OARC, Inc.
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

-- dnsjit.filter.roundrobin
-- Passthrough to other receivers in a round robin fashion
--   local filter = require("dnsjit.filter.roundrobin").new()
--   filter.receiver(...)
--   filter.receiver(...)
--   filter.receiver(...)
--   input.receiver(filter)
--
-- Filter to pass queries to others in a round robin fashion.
module(...,package.seeall)

require("dnsjit.filter.roundrobin_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "filter_roundrobin_t"
local filter_roundrobin_t = ffi.typeof(t_name)
local Roundrobin = {}

-- Create a new Roundrobin filter.
function Roundrobin.new()
    local self = {
        receivers = {},
        obj = filter_roundrobin_t(),
    }
    C.filter_roundrobin_init(self.obj)
    ffi.gc(self.obj, C.filter_roundrobin_destroy)
    return setmetatable(self, { __index = Roundrobin })
end

-- Return the Log object to control logging of this instance or module.
function Roundrobin:log()
    if self == nil then
        return C.filter_roundrobin_log()
    end
    return self.obj._log
end

function Roundrobin:receive()
    self.obj._log:debug("receive()")
    return C.filter_roundrobin_receiver(), self.obj
end

-- Set the receiver to pass queries to, this can be called multiple times to
-- set addtional receivers.
function Roundrobin:receiver(o)
    self.obj._log:debug("receiver()")
    local recv, robj = o:receive()
    local ret = C.filter_roundrobin_add(self.obj, recv, robj)
    if ret == 0 then
        table.insert(self.receivers, o)
        return
    end
    return ret
end

return Roundrobin

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

-- dnsjit.filter.multicopy
-- Pass a copy of the query to all receivers
--   local filter = require("dnsjit.filter.multicopy").new()
-- .
--   filter.receiver(...)
--   filter.receiver(...)
--   filter.receiver(...)
-- .
--   input.receiver(filter)
--
-- Filter to pass copy of queries to all registered receivers.
module(...,package.seeall)

require("dnsjit.filter.multicopy_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "filter_multicopy_t"
local filter_multicopy_t = ffi.typeof(t_name)
local Multicopy = {}

-- Create a new Multicopy filter.
function Multicopy.new()
    local self = {
        receivers = {},
        obj = filter_multicopy_t(),
    }
    C.filter_multicopy_init(self.obj)
    ffi.gc(self.obj, C.filter_multicopy_destroy)
    return setmetatable(self, { __index = Multicopy })
end

-- Return the Log object to control logging of this instance or module.
function Multicopy:log()
    if self == nil then
        return C.filter_multicopy_log()
    end
    return self.obj._log
end

function Multicopy:receive()
    self.obj._log:debug("receive()")
    return C.filter_multicopy_receiver(), self.obj
end

-- Set the receiver to pass queries to, this can be called multiple times to
-- set addtional receivers.
function Multicopy:receiver(o)
    self.obj._log:debug("receiver()")
    local recv, robj = o:receive()
    local ret = C.filter_multicopy_add(self.obj, recv, robj)
    if ret == 0 then
        table.insert(self.receivers, o)
        return
    end
    return ret
end

return Multicopy

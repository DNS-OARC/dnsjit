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

local type = "filter_multicopy_t"
local struct
local mt = {
    __gc = function(self)
        if ffi.istype(type, self) then
            C.filter_multicopy_destroy(self)
        end
    end,
    __index = {
        new = function()
            local self = struct()
            if not self then
                error("oom")
            end
            if ffi.istype(type, self) then
                C.filter_multicopy_init(self)
                return self
            end
        end
    }
}
struct = ffi.metatype(type, mt)

local Multicopy = {}

-- Create a new Multicopy filter.
function Multicopy.new()
    local o = struct.new()
    return setmetatable({
        _ = o,
        receivers = {},
    }, {__index = Multicopy})
end

-- Return the Log object to control logging of this instance or module.
function Multicopy:log()
    if self == nil then
        return C.filter_multicopy_log()
    end
    return self._._log
end

function Multicopy:receive()
    self._._log:debug("receive()")
    return C.filter_multicopy_receiver(), self._
end

-- Set the receiver to pass queries to, this can be called multiple times to
-- set addtional receivers.
function Multicopy:receiver(o)
    self._._log:debug("receiver()")
    local recv, robj
    recv, robj = o:receive()
    local ret = C.filter_multicopy_add(self._, recv, robj)
    if ret == 0 then
        table.insert(self.receivers, o)
        return
    end
    return ret
end

return Multicopy

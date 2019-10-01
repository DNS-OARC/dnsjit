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

-- dnsjit.filter.copy
-- Creates a copy of an object chain with selected object types.
--   local copy = require("dnsjit.filter.copy").new()
--   local object = require("dnsjit.core.objects")
--   copy:obj_type(object.PAYLOAD)
--   copy:obj_type(object.IP6)
--   channel:receiver(copy)
--
-- Filter to create a copy of the object chain with selected object types.
-- The user is responsible for manually freeing the created object chain.
module(...,package.seeall)

require("dnsjit.filter.copy_h")
local object = require("dnsjit.core.object")
local ffi = require("ffi")
local C = ffi.C

local t_name = "filter_copy_t"
local filter_copy_t = ffi.typeof(t_name)
local Copy = {}

-- Create a new Copy filter.
function Copy.new()
    local self = {
        obj = filter_copy_t(),
    }
    C.filter_copy_init(self.obj)
    ffi.gc(self.obj, C.filter_copy_destroy)
    return setmetatable(self, { __index = Copy })
end

-- Return the Log object to control logging of this instance or module.
function Copy:log()
    if self == nil then
        return C.filter_copy_log()
    end
    return self.obj._log
end

-- Set the object type to be copied. Can be called multiple times to copy
-- multiple object types from the object chain.
function Copy:obj_type(obj_type)
    C.filter_copy_set(self.obj, obj_type)
end

-- Return the C functions and context for receiving objects.
function Copy:receive()
    return C.filter_copy_receiver(self.obj), self.obj
end

-- Set the receiver to pass objects to.
function Copy:receiver(o)
    self.obj.recv, self.obj.recv_ctx = o:receive()
end

return Copy

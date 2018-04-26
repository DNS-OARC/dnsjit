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

-- dnsjit.output.null
-- Output to nothing (/dev/null)
--   local output = require("dnsjit.output.null").new()
--
-- Output module for those that doesn't really like packets.
module(...,package.seeall)

require("dnsjit.output.null_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_null_t"
local output_null_t = ffi.typeof(t_name)
local Null = {}

-- Create a new Null output.
function Null.new()
    local self = {
        _producer = nil,
        obj = output_null_t(),
    }
    C.output_null_init(self.obj)
    ffi.gc(self.obj, C.output_null_destroy)
    return setmetatable(self, { __index = Null })
end

-- Return the Log object to control logging of this instance or module.
function Null:log()
    if self == nil then
        return C.output_null_log()
    end
    return self.obj._log
end

-- Return the C functions and context for receiving objects.
function Null:receive()
    return C.output_null_receiver(), self.obj
end

-- Set the producer to get objects from.
function Null:producer(o)
    self.obj._log:debug("producer()")
    self.obj.prod, self.obj.ctx = o:produce()
    self._producer = o
end

-- Retrieve
-- .I num
-- objects from the producer, if
-- .I num
-- is zero or less then retrieve all objects.
-- Returns 0 if successful.
function Null:run(num)
    return C.output_null_run(self.obj, num)
end

-- Return the number of packets we sent into the void.
function Null:packets()
    return tonumber(self.obj.pkts)
end

return Null

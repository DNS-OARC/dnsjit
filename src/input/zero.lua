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

-- dnsjit.input.zero
-- Generate empty objects (/dev/zero)
--   local input = require("dnsjit.input.zero").new()
--   input:receiver(filter_or_output)
--   input:run(1e6)
--
-- Input module for generating empty
-- .I core.object.null
-- objects, mostly used for testing.
module(...,package.seeall)

require("dnsjit.input.zero_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "input_zero_t"
local input_zero_t = ffi.typeof(t_name)
local Zero = {}

-- Create a new Zero input.
function Zero.new()
    local self = {
        _receiver = nil,
        obj = input_zero_t(),
    }
    C.input_zero_init(self.obj)
    ffi.gc(self.obj, C.input_zero_destroy)
    return setmetatable(self, { __index = Zero })
end

-- Return the Log object to control logging of this instance or module.
function Zero:log()
    if self == nil then
        return C.input_zero_log()
    end
    return self.obj._log
end

-- Set the receiver to pass objects to.
function Zero:receiver(o)
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

-- Return the C functions and context for producing objects.
function Zero:produce()
    return C.input_zero_producer(), self.obj
end

-- Generate
-- .I num
-- empty objects and send them to the receiver.
function Zero:run(num)
    C.input_zero_run(self.obj, num)
end

return Zero

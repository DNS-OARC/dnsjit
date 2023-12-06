-- Copyright (c) 2018-2023, OARC, Inc.
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

-- dnsjit.filter.split
-- Passthrough to other receivers in various ways
--   local filter = require("dnsjit.filter.split").new()
--   filter.receiver(...)
--   filter.receiver(...)
--   filter.receiver(...)
--   input.receiver(filter)
--
-- Filter to pass objects to others in various ways.
module(...,package.seeall)

require("dnsjit.filter.split_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "filter_split_t"
local filter_split_t = ffi.typeof(t_name)
local Split = {}

-- Create a new Split filter.
function Split.new()
    local self = {
        receivers = {},
        obj = filter_split_t(),
    }
    C.filter_split_init(self.obj)
    ffi.gc(self.obj, C.filter_split_destroy)
    return setmetatable(self, { __index = Split })
end

-- Return the Log object to control logging of this instance or module.
function Split:log()
    if self == nil then
        return C.filter_split_log()
    end
    return self.obj._log
end

-- Set the passthrough mode to round robin (default mode).
function Split:roundrobin()
    self.obj.mode = "FILTER_SPLIT_MODE_ROUNDROBIN"
end

-- Set the passthrough mode to send to all receivers.
function Split:sendall()
    self.obj.mode = "FILTER_SPLIT_MODE_SENDALL"
end

-- Return the C functions and context for receiving objects.
function Split:receive()
    return C.filter_split_receiver(self.obj), self.obj
end

-- Set the receiver to pass objects to, this can be called multiple times to
-- set addtional receivers.
function Split:receiver(o)
    local recv, ctx = o:receive()
    C.filter_split_add(self.obj, recv, ctx)
    table.insert(self.receivers, o)
end

return Split

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

-- dnsjit.core.channel
-- A channel to send objects between threads
--   local chan = require("dnsjit.core.channel").new()
--   local thr = require("dnsjit.core.thread").new()
--   thr:start(function(thr)
--       local chan = thr:pop()
--       local obj = chan:get()
--       ...
--   end)
--   thr:push(chan)
--   chan:put(...)
--   chan:close()
--   thr:stop()
--
-- A channel can be used to send objects between threads.
module(...,package.seeall)

require("dnsjit.core.channel_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_channel_t"
local core_channel_t
local Channel = {}

-- Create a new Channel, use the optional
-- .I size
-- to specify the size of the channel (buffer).
-- Default size is 8192.
function Channel.new(size)
    if size == nil then
        size = 8192
    end
    local self = core_channel_t()
    C.core_channel_init(self, size)
    ffi.gc(self, C.core_channel_destroy)
    return self
end

-- Return the Log object to control logging of this instance or module.
function Channel:log()
    if self == nil then
        return C.core_channel_log()
    end
    return self._log
end

-- Return a void pointer, C type name and module to be able to share the
-- channel between threads.
function Channel:share()
    return ffi.cast("void*", self), t_name.."*", "dnsjit.core.channel"
end

-- Return the C functions and context for receiving objects which will put
-- a copy of the received object into the channel.
function Channel:receive()
    return C.core_channel_receiver(), self
end

-- Set the receiver to pass objects to, these objects are retrieved from
-- the channel.
function Channel:receiver(o)
    local recv, ctx = o:receive()
    self.recv = recv
    self.ctx = ctx
end

-- If you have set a receiver, start getting objects from the channel and
-- passing them to the receiver until the channel is closed.
-- Returns 0 on success.
function Channel:run()
    return C.core_channel_run(self)
end

-- Put an object into the channel, this object is not copied so you need to
-- do that yourself or make sure they are referenced objects.
-- If the channel is full then it will stall and wait until space becomes
-- available.
-- Returns 0 on success.
function Channel:put(obj)
    return C.core_channel_put(self, obj)
end

-- Get an object from the channel, if the channel is empty it will wait until
-- an object is available.
-- Returns nil if the channel is closed or on error.
function Channel:get()
    return C.core_channel_get(self)
end

-- Close the channel, returns 0 on success.
function Channel:close()
    return C.core_channel_close(self)
end

core_channel_t = ffi.metatype(t_name, { __index = Channel })

-- dnsjit.core.thread (3)
return Channel

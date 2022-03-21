-- Copyright (c) 2018-2022, OARC, Inc.
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
-- Send data to another thread
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
-- A channel can be used to send data to another thread, this is done by
-- putting a pointer to the data into a wait-free and lock-free ring buffer
-- (concurrency kit).
-- The channel uses the single producer, single consumer model (SPSC) so
-- there can only be one writer and one reader.
-- .SS Attributes
-- .TP
-- int closed
-- Is 1 if the channel has been closed.
module(...,package.seeall)

require("dnsjit.core.channel_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_channel_t"
local core_channel_t
local Channel = {}

-- Create a new Channel, use the optional
-- .I capacity
-- to specify the capacity of the channel (buffer).
-- Capacity must be a power-of-two greater than or equal to 4.
-- Default capacity is 2048.
function Channel.new(capacity)
    if capacity == nil then
        capacity = 2048
    end
    local self = core_channel_t()
    C.core_channel_init(self, capacity)
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

-- Return information to use when sharing this object between threads.
function Channel:share()
    return ffi.cast("void*", self), t_name.."*", "dnsjit.core.channel"
end

-- Put an object into the channel, if the channel is full then it will
-- stall and wait until space becomes available.
-- Object may be nil.
function Channel:put(obj)
    C.core_channel_put(self, obj)
end

-- Try and put an object into the channel.
-- Returns 0 on success.
function Channel:put(obj)
    C.core_channel_try_put(self, obj)
end

-- Get an object from the channel, if the channel is empty it will wait until
-- an object is available.
-- Returns nil if the channel is closed or if a nil object was explicitly put
-- into the channel.
function Channel:get()
    return C.core_channel_get(self)
end

-- Try and get an object from the channel.
-- Returns nil if there was no objects to get.
function Channel:try_get()
    return C.core_channel_try_get(self)
end

-- Return number of enqueued objects.
function Channel:size()
    return C.core_channel_size(self)
end

-- Returns true when channel is full.
function Channel:full()
    return C.core_channel_full(self)
end

-- Close the channel.
function Channel:close()
    C.core_channel_close(self)
end

-- Return the C functions and context for receiving objects.
function Channel:receive()
    return C.core_channel_receiver(), self
end

-- Set the receiver to pass objects to.
-- NOTE; The channel keeps no reference of the receiver, it needs to live as
-- long as the channel does.
function Channel:receiver(o)
    self.recv, self.ctx = o:receive()
end

-- Retrieve all objects from the channel and send it to the receiver.
function Channel:run()
    C.core_channel_run(self)
end

core_channel_t = ffi.metatype(t_name, { __index = Channel })

-- dnsjit.core.thread (3)
return Channel

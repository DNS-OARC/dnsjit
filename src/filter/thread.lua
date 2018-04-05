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

-- dnsjit.filter.thread
-- Send objects to a receiver in another thread
--   local input = ...
--   local thread = require("dnsjit.filter.thread").new()
--   local output = ...
--   input:receiver(thread)
--   thread:receiver(output)
--   thread:start()
--   input:run()
--   thread:stop()
--
-- NOTE; Work in progress!
-- Send objects to a receiver which will run in another thread using a
-- circular buffer.
-- Currently only support 1 producer and 1 consumer and copies objects
-- (which is a huge slowdown).
module(...,package.seeall)

require("dnsjit.filter.thread_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "filter_thread_t"
local filter_thread_t = ffi.typeof(t_name)
local Thread = {}

-- Create a new Thread filter.
function Thread.new(queue_size)
    if queue_size == nil then
        queue_size = 1000
    end
    local self = {
        receivers = {},
        obj = filter_thread_t(),
    }
    C.filter_thread_init(self.obj, queue_size)
    ffi.gc(self.obj, C.filter_thread_destroy)
    return setmetatable(self, { __index = Thread })
end

-- Return the Log object to control logging of this instance or module.
function Thread:log()
    if self == nil then
        return C.filter_thread_log()
    end
    return self.obj._log
end

-- Start the thread(s), returns 0 on success.
function Thread:start()
    return C.filter_thread_start(self.obj)
end

-- Stop the thread(s) and flush the queue, returns 0 on success.
function Thread:stop()
    return C.filter_thread_stop(self.obj)
end

-- Return the C functions and context for receiving objects.
function Thread:receive()
    self.obj._log:debug("receive()")
    return C.filter_thread_receiver(), self.obj
end

-- Set the receiver to pass queries to.
function Thread:receiver(o)
    self.obj._log:debug("receiver()")
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

return Thread

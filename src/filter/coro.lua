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

-- dnsjit.filter.coro
-- Filter through a custom Lua function
--   local filter = require("dnsjit.filter.coro").new()
--   filter:func(function(filter, object)
--      filter:send(object)
--   end)
--
-- Filter module to run custom Lua code on received objects with the option
-- to send them to the next receiver.
module(...,package.seeall)

require("dnsjit.filter.coro_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "filter_coro_t"
local filter_coro_t = ffi.typeof(t_name)
local Coro = {}

-- Create a new Coro filter.
function Coro.new()
    local self = {
        receivers = {},
        obj = filter_coro_t(),
        thread = nil,
    }
    C.filter_coro_init(self.obj)
    ffi.gc(self.obj, function(self)
        self:stop()
        C.filter_coro_destroy()
    end)
    return setmetatable(self, { __index = Coro })
end

-- Return the Log object to control logging of this instance or module.
function Coro:log()
    if self == nil then
        return C.filter_coro_log()
    end
    return self.obj._log
end

-- Set the function to call on each receive and start a coroutine.
function Coro:func(func)
    if self.thread then
        return
    end
    self.thread = coroutine.create(function()
        local self, func = coroutine.yield()
        while true do
            coroutine.yield()
            if self.obj.done == 1 then
                return
            end
            func(self, C.filter_coro_get(self.obj))
        end
    end)
    -- TODO: check return
    dnsjit_filter_coro_store_thread(self.thread)
    C.filter_coro_set_thread(self.obj)

    coroutine.resume(self.thread)
    coroutine.resume(self.thread, self, func)
end

-- Stop the coroutine.
function Coro:stop()
    if self.thread then
        self.obj.done = 1
        coroutine.resume(self.thread)
        C.filter_coro_clear_thread(self.obj)
        self.thread = nil
    end
end

-- Return the C functions and context for receiving objects.
function Coro:receive()
    self.obj._log:debug("receive()")
    return C.filter_coro_receiver(), self.obj
end

-- Set the receiver to pass queries to.
function Coro:receiver(o)
    self.obj._log:debug("receiver()")
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

-- Used from the Lua function to send objects to the next receiver,
-- returns 0 on success.
function Coro:send(object)
    return C.core_receiver_call(self.obj.recv, self.obj.ctx, object)
end

-- dnsjit.core.object (3),
-- dnsjit.filter.lua (3)
return Coro

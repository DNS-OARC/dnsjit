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
-- Filter through custom Lua code running in a real thread
--   local filter = require("dnsjit.filter.thread").new()
--   filter:create(function(thread)
--       while true do
--           local query = thread:recv()
--           if query == nil then
--               return
--           end
--           ...
--           thread:send(query)
--       end
--   end)
--   ...
--   filter:stop()
--   filter:join()
--
-- Filter module to run custom Lua code on received queries with the option
-- to send them to the next receiver.
-- This module start a real thread and passes queries through a queue.
module(...,package.seeall)

local ch = require("dnsjit.core.chelpers")
local query = require("dnsjit.core.query")
require("dnsjit.filter.thread_h")
local ffi = require("ffi")
local C = ffi.C

local type = "filter_thread_t"
local struct
local mt = {
    __gc = function(self)
        if ffi.istype(type, self) then
            C.filter_thread_destroy(self)
        end
    end,
    __index = {
        new = function()
            local self = struct()
            if not self then
                error("oom")
            end
            if ffi.istype(type, self) then
                C.filter_thread_init(self)
                return self
            end
        end
    }
}
struct = ffi.metatype(type, mt)

local Thread = {}

-- Create a new Thread filter.
function Thread.new()
    local o = struct.new()
    return setmetatable({
        inthread = false,
        given_receiver = false,
        created = false,
        _ = o,
    }, {__index = Thread})
end

-- Return the Log object to control logging of this instance or module.
function Thread:log()
    if self == nil then
        return C.filter_thread_log()
    end
    return self._._log
end

function Thread:run()
    if not THREAD_BYTECODE or string.len(THREAD_BYTECODE) < 1 then
        error("invalid call to run()")
    end
    if not THREAD_SLLQ_IN or THREAD_SLLQ_IN == nil then
        error("invalid call to run()")
    end
    self._.qin = THREAD_SLLQ_IN
    if THREAD_RECV and THREAD_RECV ~= nil then
        self._.recv = THREAD_RECV
        self._.robj = THREAD_ROBJ
    end
    self.inthread = true
    assert(loadstring(THREAD_BYTECODE))(self)
end

-- Create a new thread and call the function in it, this function runs in
-- it's own Lua state and in so does not shared any global variables.
function Thread:create(func)
    if self.created then
        error("already created thread")
    end
    if self.inthread then
        error("not usable within a thread context")
    end
    self._._log:debug("create()")
    local bc = string.dump(func)
    if C.filter_thread_create(self._, bc, string.len(bc)) > 0 then
        error("could not create thread")
    end
    self.created = true
end

-- Stop the running thread by sending a special stop query.
function Thread:stop()
    if not self.created then
        error("no thread created yet")
    end
    if self.inthread then
        error("not usable within a thread context")
    end
    self._._log:debug("stop()")
    return ch.z2n(C.filter_thread_stop(self._))
end

-- Wait for the thread to join after stopping it.
function Thread:join()
    if not self.created then
        error("no thread created yet")
    end
    if self.inthread then
        error("not usable within a thread context")
    end
    self._._log:debug("join()")
    return ch.z2n(C.filter_thread_join(self._))
end

function Thread:receive()
    if self.inthread then
        error("not usable within a thread context")
    end
    if self.given_receiver then
        error("can not receive from multiple sources")
    end
    self._._log:debug("receive()")
    self.given_receiver = true
    return C.filter_thread_receiver(), self._
end

-- Set the receiver to pass queries to.
function Thread:receiver(o)
    if self.created then
        error("unable to set receiver after thread has been created")
    end
    if self.inthread then
        error("not usable within a thread context")
    end
    self._._log:debug("receiver()")
    self._.recv, self._.robj = o:receive()
    self._receiver = o
end

-- Called in the thread function to receive queries, returns nil when the
-- special stop query has been received.
function Thread:recv()
    if not self.inthread then
        error("only usable within a thread context")
    end
    self._._log:debug("recv()")
    local q = C.filter_thread_recv(self._)
    if q ~= nil then
        self._._log:debug("recv() query.new()")
        return query.new(q)
    end
end

-- Called in the thread function to send the query to the next receiver.
function Thread:send(q)
    if not self.inthread then
        error("only usable within a thread context")
    end
    self._._log:debug("send()")
    -- TODO: test replace with ffi.gc(q:struct(), nil)
    return ch.z2n(C.filter_thread_send(self._, q:struct()))
end

-- dnsjit.filter.lua (3)
return Thread

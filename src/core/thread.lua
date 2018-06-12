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

-- dnsjit.core.thread
-- POSIX thread with separate Lua state
--   local thr = require("dnsjit.core.thread").new()
--   thr:start(function(thr)
--       print("Hello from thread")
--   end)
--   thr:stop()
--
-- Start a new POSIX thread with it's own Lua state.
-- Sharable objects can be passed to the thread by pushing and poping them of
-- the thread stack.
-- The Thread object and any other objects passed to the thread needs to be
-- kept alive as long as the thread is running.
module(...,package.seeall)

require("dnsjit.core.thread_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_thread_t"
local core_thread_t
local Thread = {
    _in_thread = function(thr, bytecode)
        thr = ffi.cast("core_thread_t*", thr)
        loadstring(bytecode)(thr)
    end
}

-- Create a new Thread object.
function Thread.new()
    local self = core_thread_t()
    C.core_thread_init(self)
    ffi.gc(self, C.core_thread_destroy)
    return self
end

-- Return the Log object to control logging of this instance or module.
function Thread:log()
    if self == nil then
        return C.core_thread_log()
    end
    return self._log
end

-- Start the thread and execute the given function in a separate Lua state,
-- first argument to the function will be the Thread object that created it.
-- Returns 0 on success.
function Thread:start(func)
    local bc = string.dump(func)
    return C.core_thread_start(self, bc, #bc)
end

-- Wait for the thread to return.
-- Returns 0 on success.
function Thread:stop()
    return C.core_thread_stop(self)
end

-- Push a string, number or sharable object onto the thread stack so it can
-- be retrieved inside the thread using
-- .IR pop() .
-- The object needs to be kept alive as long as the thread is running, strings
-- and numbers are copied.
-- Returns 0 on success.
function Thread:push(obj)
    local t = type(obj)
    if t == "string" then
        return C.core_thread_push_string(self, obj, #obj)
    elseif t == "number" then
        return C.core_thread_push_int64(self, obj)
    end
    local ptr, type, module = obj:share()
    return C.core_thread_push(self, ptr, type, #type, module, #module)
end

-- Pop a shared value off the thread stack, should only be called within the
-- thread.
-- Returns nil on failure or if no shared values are left on the stack.
function Thread:pop()
    local item = C.core_thread_pop(self)
    if item == nil then
        return
    end
    if item.ptr == nil then
        if item.str == nil then
            return tonumber(item.i64)
        end
        return ffi.string(item.str)
    end
    require(ffi.string(item.module))
    return ffi.cast(ffi.string(item.type), item.ptr)
end

core_thread_t = ffi.metatype(t_name, { __index = Thread })

-- dnsjit.core.channel (3)
return Thread

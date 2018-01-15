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

module(...,package.seeall)

local log = require("dnsjit.core.log")
local query = require("dnsjit.core.query")
require("dnsjit.filter.lua_h")
local ffi = require("ffi")
local C = ffi.C

local type = "filter_lua_t"
local struct
local mt = {
    __gc = function(self)
        if ffi.istype(type, self) then
            C.filter_lua_destroy(self)
        end
    end,
    __index = {
        new = function()
            local self = struct()
            if not self then
                error("oom")
            end
            if ffi.istype(type, self) then
                C.filter_lua_init(self)
                return self
            end
        end
    }
}
struct = ffi.metatype(type, mt)

local Lua = {}

function Lua.new()
    local o = struct.new()
    local log = log.new(o.log)
    log:debug("new()")
    return setmetatable({
        _ = o,
        log = log,
        ishandler = false,
    }, {__index = Lua})
end

function Lua:func(func)
    if self.ishandler then
        error("is handler")
    end
    local bc = string.dump(func)
    return C.filter_lua_func(self._, bc, string.len(bc))
end

function Lua:receive()
    if self.ishandler then
        error("is handler")
    end
    self.log:debug("receive()")
    return C.filter_lua_receiver(), self._
end

function Lua:receiver(o)
    if self.ishandler then
        error("is handler")
    end
    self.log:debug("receiver()")
    self._.recv, self._.robj = o:receive()
    self._receiver = o
end

function Lua.handler()
    return setmetatable({
        ishandler = true,
        _func = nil,
        _recv = nil,
        _robj = nil,
    }, {__index = Lua})
end

function Lua:decompile()
    if not self.ishandler then
        error("not handler")
    end
    self._recv = FILTER_LUA_RECV
    self._robj = FILTER_LUA_ROBJ
    self._func = loadstring(FILTER_LUA_BYTECODE)
    return
end

function Lua:run()
    if not self.ishandler then
        error("not handler")
    end
    if self._func == nil then
        return
    end
    local q = C.query_copy(FILTER_LUA_QUERY)
    return self._func(self, query.new(q))
end

function Lua:send(q)
    if not self.ishandler then
        error("not handler")
    end
    local q = C.query_copy(q:struct())
    return C.receiver_call(self._recv, self._robj, q)
end

return Lua

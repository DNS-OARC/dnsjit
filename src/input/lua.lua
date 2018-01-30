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

-- dnsjit.input.lua
-- Generate input from Lua
--   local input = require("dnsjit.input.lua").new()
--   input:receiver(filter_or_output)
--   input:send(query)
--
-- An input module to generate input from Lua.
-- .LP
-- .B NOTE
-- there is no way to create queries yet.
module(...,package.seeall)

local ch = require("dnsjit.core.chelpers")
local log = require("dnsjit.core.log")
require("dnsjit.core.log_h")
require("dnsjit.core.receiver_h")
local ffi = require("ffi")
local C = ffi.C

local Lua = {}

-- Create a new Lua input.
function Lua.new()
    local o = ffi.new("log_t")
    local log = log.new(o)
    log:debug("new()")
    return setmetatable({
        _recv = nil,
        _robj = nil,
        _receiver = nil,
        _log = o,
        log = log,
    }, {__index = Lua})
end

-- Set the receiver to pass queries to.
function Lua:receiver(o)
    self.log:debug("receiver()")
    self._recv, self._robj = o:receive()
    self._receiver = o
end

-- Send a query to the receiver.
function Lua:send(q)
    self.log:debug("send()")
    return ch.z2n(C.receiver_call(self._recv, self._robj, q:struct()))
end

-- dnsjit.core.query (3)
return Lua

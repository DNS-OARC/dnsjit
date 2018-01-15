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
require("dnsjit.output.null_h")
local ffi = require("ffi")
local C = ffi.C

local type = "output_null_t"
local struct
local mt = {
    __index = {
        new = function()
            local self = struct()
            if not self then
                error("oom")
            end
            return self
        end
    }
}
struct = ffi.metatype(type, mt)

local Null = {}

function Null.new()
    local o = struct.new()
    local log = log.new(o.log)
    log:debug("new()")
    return setmetatable({
        _ = o,
        log = log,
    }, {__index = Null})
end

function Null:receive()
    self.log:debug("receive()")
    return C.output_null_receiver(), self._
end

function Null:packets()
    return tonumber(self._.pkts)
end

return Null

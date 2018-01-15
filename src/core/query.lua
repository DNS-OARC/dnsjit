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
require("dnsjit.core.query_h")
local ffi = require("ffi")
local C = ffi.C

local type = "query_t"
local struct
local mt = {
    __gc = function(self)
        if ffi.istype(type, self) then
            C.query_destroy(self)
        end
    end,
    __index = {
        new = function()
            local self = struct()
            if not self then
                error("oom")
            end
            if ffi.istype(type, self) then
                C.query_init(self)
                return self
            end
        end
    }
}
struct = ffi.metatype(type, mt)

local Query = {}

function Query.new(o)
    if ffi.istype(type, o) and o ~= nil then
        ffi.gc(o, C.query_free)
    else
        o = struct.new()
    end
    local log = log.new(o.log)
    log:debug("new()")
    return setmetatable({
        _ = o,
        log = log,
    }, {__index = Query})
end

function Query:struct()
    self.log:debug("struct()")
    return self._
end

return Query

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
require("dnsjit.filter.timing_h")
local ffi = require("ffi")
local C = ffi.C

local type = "filter_timing_t"
local struct
local mt = {
    __gc = function(self)
        if ffi.istype(type, self) then
            C.filter_timing_destroy(self)
        end
    end,
    __index = {
        new = function()
            local self = struct()
            if not self then
                error("oom")
            end
            if ffi.istype(type, self) then
                C.filter_timing_init(self)
                return self
            end
        end
    }
}
struct = ffi.metatype(type, mt)

local Timing = {}

function Timing.new()
    local o = struct.new()
    local log = log.new(o.log)
    log:debug("new()")
    return setmetatable({
        _ = o,
        log = log,
    }, {__index = Timing})
end

function Timing:keep()
    self._.mode = "TIMING_MODE_KEEP"
end

function Timing:increase(ns)
    self._.mode = "TIMING_MODE_INCREASE"
    self._.inc = ns
end

function Timing:reduce(ns)
    self._.mode = "TIMING_MODE_REDUCE"
    self._.red = ns
end

function Timing:multiply(factor)
    self._.mode = "TIMING_MODE_MULTIPLY"
    self._.mul = factor
end

function Timing:bestEffort()
    self._.mode = "TIMING_MODE_BEST_EFFORT"
end

function Timing:receive()
    self.log:debug("receive()")
    return C.filter_timing_receiver(), self._
end

function Timing:receiver(o)
    self.log:debug("receiver()")
    self._.recv, self._.robj = o:receive()
    self._receiver = o
end

return Timing

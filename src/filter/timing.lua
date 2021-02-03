-- Copyright (c) 2018-2021, OARC, Inc.
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

-- dnsjit.filter.timing
-- Filter to pass objects to the next receiver based on timing between packets
--   local filter = require("dnsjit.filter.timing").new()
--   ...
--   filter:receiver(...)
--
-- Filter to manipulate processing so it simulates the actual timing when
-- packets arrived or to delay processing.
module(...,package.seeall)

require("dnsjit.filter.timing_h")
local ffi = require("ffi")
local C = ffi.C

local Timing = {}

-- Create a new Timing filter.
function Timing.new()
    local self = {
        _receiver = nil,
        obj = C.filter_timing_new(),
    }
    ffi.gc(self.obj, C.filter_timing_free)
    return setmetatable(self, { __index = Timing })
end

-- Return the Log object to control logging of this instance or module.
function Timing:log()
    if self == nil then
        return C.filter_timing_log()
    end
    return self.obj._log
end

-- Set the timing mode to keep the timing between packets.
function Timing:keep()
    self.obj.mode = "TIMING_MODE_KEEP"
end

-- Set the timing mode to increase the timing between packets by the given
-- number of nanoseconds.
function Timing:increase(ns)
    self.obj.mode = "TIMING_MODE_INCREASE"
    self.obj.inc = ns
end

-- Set the timing mode to reduce the timing between packets by the given
-- number of nanoseconds.
function Timing:reduce(ns)
    self.obj.mode = "TIMING_MODE_REDUCE"
    self.obj.red = ns
end

-- Set the timing mode to multiply the timing between packets by the given
-- factor (float/double).
function Timing:multiply(factor)
    self.obj.mode = "TIMING_MODE_MULTIPLY"
    self.obj.mul = factor
end

-- Set the timing mode to a fixed number of nanoseconds between packets.
function Timing:fixed(ns)
    self.obj.mode = "TIMING_MODE_FIXED"
    self.obj.fixed = ns
end

-- Set the timing mode to simulate the timing of packets in realtime.
-- Packets are processed in batches of given size (default 128) before
-- adjusting time. Aborts if real time drifts ahead more than given
-- number of seconds (default 1.0s).
function Timing:realtime(drift, batch_size)
    self.obj.mode = "TIMING_MODE_REALTIME"
    if drift == nil then
        drift = 1
    end
    if batch_size == nil then
        batch_size = 128
    end
    self.obj.rt_batch = batch_size
    self.obj.rt_drift = math.floor(drift * 1000000000)
end

-- Return the C functions and context for receiving objects.
function Timing:receive()
    return C.filter_timing_receiver(), self.obj
end

-- Set the receiver to pass objects to.
function Timing:receiver(o)
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

-- Return the C functions and context for producing objects.
function Timing:produce()
    return C.filter_timing_producer(self.obj), self.obj
end

-- Set the producer to get objects from.
function Timing:producer(o)
    self.obj.prod, self.obj.prod_ctx = o:produce()
    self._producer = o
end

return Timing

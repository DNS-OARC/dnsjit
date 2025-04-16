-- Copyright (c) 2018-2025 OARC, Inc.
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

-- dnsjit.lib.clock
-- Clock and time functions
--   local clock = require("dnsjit.lib.clock")
--   local sec, nsec = clock.monotonic()
--
-- Functions to get the time from system-wide clocks.
module(...,package.seeall)

require("dnsjit.lib.clock_h")
local C = require("ffi").C

Clock = {}

-- Return the current seconds and nanoseconds (as a list) from the realtime
-- clock.
function Clock.realtime()
    local ts = C.lib_clock_gettime("LIB_CLOCK_REALTIME")
    return tonumber(ts.sec), tonumber(ts.nsec)
end

-- Return the current seconds and nanoseconds (as a list) from the monotonic
-- clock.
function Clock.monotonic()
    local ts = C.lib_clock_gettime("LIB_CLOCK_MONOTONIC")
    return tonumber(ts.sec), tonumber(ts.nsec)
end

-- clock_gettime (2)
return Clock

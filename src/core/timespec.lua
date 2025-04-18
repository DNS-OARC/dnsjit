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

-- dnsjit.core.receiver
-- Non-system depended time specification structure definition
--   typedef struct core_timespec {
--       int64_t sec;
--       int64_t nsec;
--   } core_timespec_t;
-- .SS C
--   #include "core/timespec.h"
-- .SS Lua
--   require("dnsjit.core.timespec_h")
-- .SS Lua functions
--   local ts = require("dnsjit.core.timespec"):max_init()
--
-- Mainly used in C modules for a system independent time specification
-- structure that can be passed to Lua.
module(...,package.seeall)

require("dnsjit.core.timespec_h")

local ffi = require("ffi")

local Timespec = {}

-- Return a new structure with both
-- .I sec
-- and
-- .I nsec
-- set to 2LL ^ 62, the maximum positive values according to Lua.
function Timespec:max_init()
    local ts = ffi.new("core_timespec_t")
    ts.sec = 2LL ^ 62
    ts.nsec = 2LL ^ 62
    return ts
end

return Timespec

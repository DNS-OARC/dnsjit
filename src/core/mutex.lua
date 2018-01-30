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

-- dnsjit.core.mutex
-- Core mutex functions
--   local mutex = require("dnsjit.core.mutex")
--   mutex.lock()
--   mutex.unlock()
--
-- Provide an interface to a mutex that is shared between all threads and
-- Lua states, this can be used to guarantee propper handling of Lua global
-- variables or anything else that might otherwise be thread unsafe.
module(...,package.seeall)

require("dnsjit.core.mutex_h")
local C = require("ffi").C

-- Lock the global shared mutex
function lock()
    return C.core_mutex_lock()
end

-- Unlock the global shared mutex
function unlock()
    return C.core_mutex_unlock()
end

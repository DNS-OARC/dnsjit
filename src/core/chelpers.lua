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

-- dnsjit.core.chelpers
-- C helper functions
--   local ch = require("dnsjit.core.chelpers")
--   function Example()
--       return ch.z2n(C.function())
--   end
--
-- The C helper functions can be used to facilitate the handling of arguments
-- to and from C functions.
module(...,package.seeall)

-- Convert the Lua
-- .I bool
-- to 1 (true) or 0 (false)
function b2i(bool)
    if bool == true then
        return 1
    elseif bool == false then
        return 0
    end
end

-- Convert a C
-- .I int
-- to false (0) or true (anything else)
function i2b(int)
    if int == 0 then
        return false
    end
    return true
end

-- Return the C
-- .I int
-- if it is 0, otherwise return nothing (empty list)
function z2n(int)
    if not int == 0 then
        return int
    end
end

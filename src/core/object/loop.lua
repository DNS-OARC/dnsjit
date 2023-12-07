-- Copyright (c) 2018-2023, OARC, Inc.
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

-- dnsjit.core.object.loop
-- OpenBSD loopback encapsulation (loop) part of a packet
--
-- The loop part of a packet that usually can be found in the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- family
-- The link-layer header describing what type of packet is encapsulated.
module(...,package.seeall)

require("dnsjit.core.object.loop_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_loop_t"
local core_object_loop_t
local Loop = {}

-- Return the textual type of the object.
function Loop:type()
    return "loop"
end

-- Return the previous object.
function Loop:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Loop:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Loop:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Loop:copy()
    return C.core_object_loop_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Loop:free()
    C.core_object_loop_free(self)
end

core_object_loop_t = ffi.metatype(t_name, { __index = Loop })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Loop

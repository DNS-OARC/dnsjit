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

-- dnsjit.core.object.udp
-- An UDP packet
--
-- An UDP packet which is usually at the top of the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- sport
-- Source port.
-- .TP
-- dport
-- Destination port.
-- .TP
-- ulen
-- UDP length (as described in the UDP header).
-- .TP
-- sum
-- Checksum.
-- .TP
-- payload
-- A pointer to the payload.
-- .TP
-- len
-- The length of the payload.
module(...,package.seeall)

require("dnsjit.core.object.udp_h")
local ffi = require("ffi")

local t_name = "core_object_udp_t"
local core_object_udp_t
local Udp = {}

-- Return the textual type of the object.
function Udp:type()
    return "udp"
end

-- Return the previous object.
function Udp:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Udp:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Udp:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Udp:copy()
    return C.core_object_udp_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Udp:free()
    C.core_object_udp_free(self)
end

core_object_udp_t = ffi.metatype(t_name, { __index = Udp })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Udp

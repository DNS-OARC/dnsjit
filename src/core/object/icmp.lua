-- Copyright (c) 2018-2024 OARC, Inc.
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

-- dnsjit.core.object.icmp
-- An ICMP packet
--
-- An ICMP packet which is usually at the top of the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- type
-- The type of ICMP message.
-- .TP
-- code
-- The (response/error) code for the ICMP type message.
-- .TP
-- cksum
-- The ICMP checksum.
module(...,package.seeall)

require("dnsjit.core.object.icmp_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_icmp_t"
local core_object_icmp_t
local Icmp = {}

-- Return the textual type of the object.
function Icmp:type()
    return "icmp"
end

-- Return the previous object.
function Icmp:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Icmp:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Icmp:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Icmp:copy()
    return C.core_object_icmp_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Icmp:free()
    C.core_object_icmp_free(self)
end

core_object_icmp_t = ffi.metatype(t_name, { __index = Icmp })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Icmp

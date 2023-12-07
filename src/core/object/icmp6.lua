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

-- dnsjit.core.object.icmp6
-- An ICMPv6 packet
--
-- An ICMPv6 packet which is usually at the top of the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- type
-- The type of ICMPv6 message.
-- .TP
-- code
-- The (response/error) code for the ICMPv6 type message.
-- .TP
-- cksum
-- The ICMPv6 checksum.
module(...,package.seeall)

require("dnsjit.core.object.icmp6_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_icmp6_t"
local core_object_icmp6_t
local Icmp6 = {}

-- Return the textual type of the object.
function Icmp6:type()
    return "icmp6"
end

-- Return the previous object.
function Icmp6:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Icmp6:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Icmp6:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Icmp6:copy()
    return C.core_object_icmp6_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Icmp6:free()
    C.core_object_icmp6_free(self)
end

core_object_icmp6_t = ffi.metatype(t_name, { __index = Icmp6 })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Icmp6

-- Copyright (c) 2018-2020, OARC, Inc.
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

-- dnsjit.core.object.gre
-- Generic Routing Encapsulation (GRE) part of a packet
--
-- The GRE part of a packet that usually can be found in the object chain
-- after parsing with, for example, Layer filter.
-- See RFC 1701.
-- .SS Attributes
-- .TP
-- gre_flags
-- The GRE flags.
-- .TP
-- ether_type
-- The protocol type of the payload packet.
-- .TP
-- checksum
-- The checksum of the GRE header and the payload packet.
-- .TP
-- key
-- The Key field contains a four octet number which was inserted by
-- the encapsulator.
-- .TP
-- sequence
-- The Sequence Number field contains an unsigned 32 bit integer which is
-- inserted by the encapsulator.
module(...,package.seeall)

require("dnsjit.core.object.gre_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_gre_t"
local core_object_gre_t
local Gre = {}

-- Return the textual type of the object.
function Gre:type()
    return "gre"
end

-- Return the previous object.
function Gre:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Gre:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Gre:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Gre:copy()
    return C.core_object_gre_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Gre:free()
    C.core_object_gre_free(self)
end

core_object_gre_t = ffi.metatype(t_name, { __index = Gre })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Gre

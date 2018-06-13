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

-- dnsjit.core.object.ieee802
-- IEEE802 part of a packet
--
-- The IEEE802 part of a packet that usually can be found in the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- tpid
-- Tag protocol identifier.
-- .TP
-- pcp
-- Priority code point.
-- .TP
-- dei
-- Drop eligible indicator.
-- .TP
-- vid
-- VLAN identifier.
-- .TP
-- ether_type
-- The packet type ID field / EtherType field.
module(...,package.seeall)

require("dnsjit.core.object.ieee802_h")
local ffi = require("ffi")

local t_name = "core_object_ieee802_t"
local core_object_ieee802_t
local Ieee802 = {}

-- Return the textual type of the object.
function Ieee802:type()
    return "ieee802"
end

-- Return the previous object.
function Ieee802:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Ieee802:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Ieee802:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Ieee802:copy()
    return C.core_object_ieee802_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Ieee802:free()
    C.core_object_ieee802_free(self)
end

core_object_ieee802_t = ffi.metatype(t_name, { __index = Ieee802 })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Ieee802

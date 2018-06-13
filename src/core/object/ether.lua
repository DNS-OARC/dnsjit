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

-- dnsjit.core.object.ether
-- Ether part of a packet
--
-- The ether part of a packet that usually can be found in the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- dhost
-- The destination ether address.
-- .TP
-- shost
-- The source ether address.
-- .TP
-- type
-- The packet type ID field / EtherType field.
module(...,package.seeall)

require("dnsjit.core.object.ether_h")
local ffi = require("ffi")

local t_name = "core_object_ether_t"
local core_object_ether_t
local Ether = {}

-- Return the textual type of the object.
function Ether:type()
    return "ether"
end

-- Return the previous object.
function Ether:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Ether:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Ether:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Ether:copy()
    return C.core_object_ether_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Ether:free()
    C.core_object_ether_free(self)
end

core_object_ether_t = ffi.metatype(t_name, { __index = Ether })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Ether

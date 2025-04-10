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

-- dnsjit.core.object.linuxsll2
-- Linux cooked-mode v2 capture (SLL2) part of a packet
--
-- The SLL2 part of a packet that usually can be found in the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- protocol_type
-- The protocol type.
-- .TP
-- reserved
-- Reserved (MBZ).
-- .TP
-- interface_index
-- The interface index, on the machine on which the capture is done, of the interface on which the packet was sent or received.
-- .TP
-- arphrd_type
-- The link-layer device type.
-- .TP
-- packet_type
-- The packet type.
-- .TP
-- link_layer_address_length
-- The length of the link-layer address.
-- .TP
-- link_layer_address
-- The link-layer address.
module(...,package.seeall)

require("dnsjit.core.object.linuxsll2_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_linuxsll2_t"
local core_object_linuxsll2_t
local Linuxsll2 = {}

-- Return the textual type of the object.
function Linuxsll2:type()
    return "linuxsll2"
end

-- Return the previous object.
function Linuxsll2:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Linuxsll2:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Linuxsll2:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Linuxsll2:copy()
    return C.core_object_linuxsll2_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Linuxsll2:free()
    C.core_object_linuxsll2_free(self)
end

core_object_linuxsll2_t = ffi.metatype(t_name, { __index = Linuxsll2 })

-- dnsjit.core.object (3).
-- dnsjit.filter.layer (3)
return Linuxsll2

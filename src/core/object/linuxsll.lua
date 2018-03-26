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

-- dnsjit.core.object.linuxsll
-- Linux cooked-mode capture (SLL) part of a packet
--
-- The SLL part of a packet that usually can be found in the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- packet_type
-- The packet type.
-- .TP
-- arp_hardware
-- The link-layer device type.
-- .TP
-- link_layer_address_length
-- The length of the link-layer address.
-- .TP
-- link_layer_address
-- The link-layer address.
-- .TP
-- ether_type
-- An Ethernet protocol type.
module(...,package.seeall)

require("dnsjit.core.object.linuxsll_h")
local ffi = require("ffi")

local t_name = "core_object_linuxsll_t"
local core_object_linuxsll_t
local Linuxsll = {}

-- Return the textual type of the object.
function Linuxsll:type()
    return "linuxsll"
end

-- Return the previous object.
function Linuxsll:prev()
    return self.obj_prev
end

core_object_linuxsll_t = ffi.metatype(t_name, { __index = Linuxsll })

-- dnsjit.core.object (3).
-- dnsjit.filter.layer (3)
return Linuxsll

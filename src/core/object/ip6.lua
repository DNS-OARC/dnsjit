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

-- dnsjit.core.object.ip6
-- An IPv6 packet
--
-- An IPv6 packet that usually can be found in the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- flow
-- 4 bits version, 8 bits TC and 20 bits flow-ID.
-- .TP
-- plen
-- Payload length (as in the IPv6 header).
-- .TP
-- nxt
-- Next header.
-- .TP
-- hlim
-- Hop limit.
-- .TP
-- src
-- Source address.
-- .TP
-- dst
-- Destination address.
-- .TP
-- is_frag
-- 1 bit, set if packet is a fragment.
-- .TP
-- have_rtdst
-- 1 bit, set if
-- .I rtdst
-- is set.
-- .TP
-- frag_offlg
-- Offset, reserved, and flag taken from the fragment header.
-- .TP
-- frag_ident
-- Identification taken from the fragment header.
-- .TP
-- rtdst
-- Destination address found in the routing extension header.
-- .TP
-- payload
-- A pointer to the payload.
-- .TP
-- len
-- The length of the payload.
-- .TP
-- pad_len
-- The length of padding found, if any.
module(...,package.seeall)

require("dnsjit.core.object.ip6_h")
local ffi = require("ffi")

local t_name = "core_object_ip6_t"
local core_object_ip6_t
local Ip6 = {}

-- Return the textual type of the object.
function Ip6:type()
    return "ip6"
end

-- Return the previous object.
function Ip6:prev()
    return self.obj_prev
end

core_object_ip6_t = ffi.metatype(t_name, { __index = Ip6 })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Ip6

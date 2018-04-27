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

-- dnsjit.core.object.ip
-- An IP packet
--
-- An IP packet that usually can be found in the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- v
-- Version.
-- .TP
-- hl
-- Header length.
-- .TP
-- tos
-- Type of service.
-- .TP
-- len
-- Total length.
-- .TP
-- id
-- Identification.
-- .TP
-- off
-- Fragment offset field.
-- .TP
-- ttl
-- Time to live.
-- .TP
-- p
-- Protocol.
-- .TP
-- sum
-- Checksum.
-- .TP
-- src
-- Source address.
-- .TP
-- dst
-- Destination address.
-- .TP
-- payload
-- A pointer to the payload.
-- .TP
-- plen
-- The length of the payload.
-- .TP
-- pad_len
-- The length of padding found, if any.
module(...,package.seeall)

require("dnsjit.core.object.ip_h")
local ffi = require("ffi")

local t_name = "core_object_ip_t"
local core_object_ip_t
local Ip = {}

-- Return the textual type of the object.
function Ip:type()
    return "ip"
end

-- Return the previous object.
function Ip:prev()
    return self.obj_prev
end

core_object_ip_t = ffi.metatype(t_name, { __index = Ip })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Ip

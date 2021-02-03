-- Copyright (c) 2018-2021, OARC, Inc.
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

-- dnsjit.core.object.tcp
-- A TCP segment header
--
-- A TCP segment header.
-- The data itself is in the
-- .I dnsjit.core.object.payload
-- object, which is the next object in the chain after parsing with,
-- for example,
-- .IR dnsjit.filter.layer .
-- .SS Attributes
-- .TP
-- sport
-- Source port.
-- .TP
-- dport
-- Destination port.
-- .TP
-- seq
-- Sequence number.
-- .TP
-- ack
-- Acknowledgement number.
-- .TP
-- off
-- Data offset.
-- .TP
-- x2
-- Unused.
-- .TP
-- flags
-- TCP flags.
-- .TP
-- win
-- Window.
-- .TP
-- sum
-- Checksum.
-- .TP
-- urp
-- Urgent pointer.
-- .TP
-- opts
-- Array of bytes with the TCP options found.
-- .TP
-- opts_len
-- Length of the TCP options.
module(...,package.seeall)

require("dnsjit.core.object.tcp_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_tcp_t"
local core_object_tcp_t
local Tcp = {}

-- Return the textual type of the object.
function Tcp:type()
    return "tcp"
end

-- Return the previous object.
function Tcp:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Tcp:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Tcp:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Tcp:copy()
    return C.core_object_tcp_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Tcp:free()
    C.core_object_tcp_free(self)
end

core_object_tcp_t = ffi.metatype(t_name, { __index = Tcp })

-- dnsjit.core.object (3),
-- dnsjit.core.object.payload (3),
-- dnsjit.filter.layer (3)
return Tcp

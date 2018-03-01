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

-- dnsjit.core.object.packet
-- Container of a packet
--   require("dnsjit.core.object.packet")
--   print(pkt:src(), pkt:dst())
--
-- The object that describes a packet
-- .SS Attributes
-- .TP
-- src_id
-- Source ID, used to track the packet through the input, filter and output
-- modules.
-- See also
-- .BR dnsjit.core.tracking (3).
-- .TP
-- qr_id
-- Query/Response ID, used to track the packet through the input, filter
-- and output modules.
-- See also
-- .BR dnsjit.core.tracking (3).
-- .TP
-- dst_id
-- Destination ID, used to track the packet through the input, filter
-- and output modules.
-- See also
-- .BR dnsjit.core.tracking (3).
-- .TP
-- is_udp
-- Set to 1 if this is an UDP packet.
-- .TP
-- is_tcp
-- Set to 1 if this is a TCP packet.
-- .TP
-- is_ipv6
-- Set to 1 of this is an IPV6 packet.
-- .TP
-- sport
-- Source port.
-- .TP
-- dport
-- Destination port.
-- .TP
-- ts
-- The timestamp of the packet captured or received.
-- See
-- .BR dnsjit.core.timespec (3).
-- .TP
-- payload
-- A pointer to the payload of the packet.
-- .TP
-- len
-- The length of the payload.
module(...,package.seeall)

require("dnsjit.core.object.packet_h")
local ffi = require("ffi")
local C = ffi.C
ffi.cdef[[
void free(void *);
]]

local t_name = "core_object_packet_t"
local core_object_packet_t
local Packet = {}

-- Return the textual type of the object.
function Packet:type()
    return "packet"
end

-- Return the previous object.
function Packet:prev()
    return self.obj_prev
end

-- Return the IP source as a string.
function Packet:src()
    local ptr = C.core_object_packet_src(self)
    if ptr == nil then
        return
    end
    local str = ffi.string(ptr)
    C.free(ptr)
    return str
end

-- Return the IP destination as a string.
function Packet:dst()
    local ptr = C.core_object_packet_dst(self)
    if ptr == nil then
        return
    end
    local str = ffi.string(ptr)
    C.free(ptr)
    return str
end

core_object_packet_t = ffi.metatype(t_name, { __index = Packet })

-- dnsjit.core.object (3),
-- dnsjit.core.tracking (3)
return Packet

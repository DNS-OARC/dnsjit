-- Copyright (c) 2018-2025 OARC, Inc.
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

-- dnsjit.core.object
-- Base object that is passed between receiver and receivee
--   require("dnsjit.core.object")
--   print(object:type())
--   packet = object:cast()
--
-- This is the base object that can be casted to other objects that to
-- describe a DNS message, how it was captured or generated.
-- Objects can be chained together, for example a DNS message is created
-- ontop of a packet.
-- .SS Attributes
-- .TP
-- obj_type
-- The enum of the object type.
-- .TP
-- obj_prev
-- The previous object in the object chain.
module(...,package.seeall)

require("dnsjit.core.object_h")
require("dnsjit.core.object.pcap_h")
require("dnsjit.core.object.ether_h")
require("dnsjit.core.object.null_h")
require("dnsjit.core.object.loop_h")
require("dnsjit.core.object.linuxsll_h")
require("dnsjit.core.object.linuxsll2_h")
require("dnsjit.core.object.ieee802_h")
require("dnsjit.core.object.gre_h")
require("dnsjit.core.object.ip_h")
require("dnsjit.core.object.ip6_h")
require("dnsjit.core.object.icmp_h")
require("dnsjit.core.object.icmp6_h")
require("dnsjit.core.object.udp_h")
require("dnsjit.core.object.tcp_h")
require("dnsjit.core.object.payload_h")
require("dnsjit.core.object.dns_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_t"
local core_object_t
local Object = {
    NONE = 0,
    PCAP = 1,
    ETHER = 10,
    NULL = 11,
    LOOP = 12,
    LINUXSLL = 13,
    IEEE802 = 14,
    GRE = 15,
    LINUXSLL2 = 16,
    IP = 20,
    IP6 = 21,
    ICMP = 22,
    ICMP6 = 23,
    UDP = 30,
    TCP = 31,
    PAYLOAD = 40,
    DNS = 50
}

local _type = {}
_type[Object.PCAP] = "pcap"
_type[Object.ETHER] = "ether"
_type[Object.NULL] = "null"
_type[Object.LOOP] = "loop"
_type[Object.LINUXSLL] = "linuxsll"
_type[Object.IEEE802] = "ieee802"
_type[Object.GRE] = "gre"
_type[Object.LINUXSLL2] = "linuxsll2"
_type[Object.IP] = "ip"
_type[Object.IP6] = "ip6"
_type[Object.ICMP] = "icmp"
_type[Object.ICMP6] = "icmp6"
_type[Object.UDP] = "udp"
_type[Object.TCP] = "tcp"
_type[Object.PAYLOAD] = "payload"
_type[Object.DNS] = "dns"

_type[Object.NONE] = "none"

-- Return the textual type of the object.
function Object:type()
    return _type[self.obj_type]
end

-- Return the previous object.
function Object:prev()
    return self.obj_prev
end

local _cast = {}
_cast[Object.PCAP] = "core_object_pcap_t*"
_cast[Object.ETHER] = "core_object_ether_t*"
_cast[Object.NULL] = "core_object_null_t*"
_cast[Object.LOOP] = "core_object_loop_t*"
_cast[Object.LINUXSLL] = "core_object_linuxsll_t*"
_cast[Object.IEEE802] = "core_object_ieee802_t*"
_cast[Object.GRE] = "core_object_gre_t*"
_cast[Object.LINUXSLL2] = "core_object_linuxsll2_t*"
_cast[Object.IP] = "core_object_ip_t*"
_cast[Object.IP6] = "core_object_ip6_t*"
_cast[Object.ICMP] = "core_object_icmp_t*"
_cast[Object.ICMP6] = "core_object_icmp6_t*"
_cast[Object.UDP] = "core_object_udp_t*"
_cast[Object.TCP] = "core_object_tcp_t*"
_cast[Object.PAYLOAD] = "core_object_payload_t*"
_cast[Object.DNS] = "core_object_dns_t*"

-- Cast the object to the underlining object module and return it.
function Object:cast()
    return ffi.cast(_cast[self.obj_type], self)
end

-- Cast the object to the specified object module and return it.
-- Returns nil if the object chain doesn't contained the specified object type.
function Object:cast_to(obj_type)
    if obj_type == nil then
        obj_type = self.obj_type
    end

    local obj = self
    while obj.obj_type ~= obj_type do
        obj = obj.obj_prev
        if obj == nil then return nil end
    end

    return ffi.cast(_cast[obj_type], obj)
end

-- Cast the object to the generic object module and return it.
function Object:uncast()
    return self
end

-- Make a copy of the object and return it.
function Object:copy()
    return C.core_object_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Object:free()
    C.core_object_free(self)
end

core_object_t = ffi.metatype(t_name, { __index = Object })

-- dnsjit.core.object.pcap (3),
-- dnsjit.core.object.ether (3),
-- dnsjit.core.object.null (3),
-- dnsjit.core.object.loop (3),
-- dnsjit.core.object.linuxsll (3),
-- dnsjit.core.object.linuxsll2 (3),
-- dnsjit.core.object.ieee802 (3),
-- dnsjit.core.object.gre (3),
-- dnsjit.core.object.ip (3),
-- dnsjit.core.object.ip6 (3),
-- dnsjit.core.object.icmp (3),
-- dnsjit.core.object.icmp6 (3),
-- dnsjit.core.object.udp (3),
-- dnsjit.core.object.tcp (3),
-- dnsjit.core.object.payload (3),
-- dnsjit.core.object.dns (3)
return Object

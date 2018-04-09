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
require("dnsjit.core.object.ieee802_h")
require("dnsjit.core.object.gre_h")
require("dnsjit.core.object.ip_h")
require("dnsjit.core.object.ip6_h")
require("dnsjit.core.object.icmp_h")
require("dnsjit.core.object.icmp6_h")
require("dnsjit.core.object.udp_h")
require("dnsjit.core.object.tcp_h")
require("dnsjit.core.object.packet_h")
require("dnsjit.core.object.dns_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_t"
local core_object_t
local Object = {
    CORE_OBJECT_NONE = 0,
    CORE_OBJECT_PCAP = 1,
    CORE_OBJECT_ETHER = 10,
    CORE_OBJECT_NULL = 11,
    CORE_OBJECT_LOOP = 12,
    CORE_OBJECT_LINUXSLL = 13,
    CORE_OBJECT_IEEE802 = 14,
    CORE_OBJECT_GRE = 15,
    CORE_OBJECT_IP = 20,
    CORE_OBJECT_IP6 = 21,
    CORE_OBJECT_ICMP = 22,
    CORE_OBJECT_ICMP6 = 23,
    CORE_OBJECT_UDP = 30,
    CORE_OBJECT_TCP = 31,
    CORE_OBJECT_PACKET = 32,
    CORE_OBJECT_DNS = 40
}

local _type = {}
_type[Object.CORE_OBJECT_PCAP] = "pcap"
_type[Object.CORE_OBJECT_ETHER] = "ether"
_type[Object.CORE_OBJECT_NULL] = "null"
_type[Object.CORE_OBJECT_LOOP] = "loop"
_type[Object.CORE_OBJECT_LINUXSLL] = "linuxsll"
_type[Object.CORE_OBJECT_IEEE802] = "ieee802"
_type[Object.CORE_OBJECT_GRE] = "gre"
_type[Object.CORE_OBJECT_IP] = "ip"
_type[Object.CORE_OBJECT_IP6] = "ip6"
_type[Object.CORE_OBJECT_ICMP] = "icmp"
_type[Object.CORE_OBJECT_ICMP6] = "icmp6"
_type[Object.CORE_OBJECT_UDP] = "udp"
_type[Object.CORE_OBJECT_TCP] = "tcp"
_type[Object.CORE_OBJECT_PACKET] = "packet"
_type[Object.CORE_OBJECT_DNS] = "dns"

_type[Object.CORE_OBJECT_NONE] = "none"

-- Return the textual type of the object.
function Object:type()
    return ffi.cast(_type[self.obj_type], self)
end

-- Return the previous object.
function Object:prev()
    return self.obj_prev
end

local _cast = {}
_cast[Object.CORE_OBJECT_PCAP] = "core_object_pcap_t*"
_cast[Object.CORE_OBJECT_ETHER] = "core_object_ether_t*"
_cast[Object.CORE_OBJECT_NULL] = "core_object_null_t*"
_cast[Object.CORE_OBJECT_LOOP] = "core_object_loop_t*"
_cast[Object.CORE_OBJECT_LINUXSLL] = "core_object_linuxsll_t*"
_cast[Object.CORE_OBJECT_IEEE802] = "core_object_ieee802_t*"
_cast[Object.CORE_OBJECT_GRE] = "core_object_gre_t*"
_cast[Object.CORE_OBJECT_IP] = "core_object_ip_t*"
_cast[Object.CORE_OBJECT_IP6] = "core_object_ip6_t*"
_cast[Object.CORE_OBJECT_ICMP] = "core_object_icmp_t*"
_cast[Object.CORE_OBJECT_ICMP6] = "core_object_icmp6_t*"
_cast[Object.CORE_OBJECT_UDP] = "core_object_udp_t*"
_cast[Object.CORE_OBJECT_TCP] = "core_object_tcp_t*"
_cast[Object.CORE_OBJECT_PACKET] = "core_object_packet_t*"
_cast[Object.CORE_OBJECT_DNS] = "core_object_dns_t*"

-- Cast the object to the underlining object module and return it.
function Object:cast()
    return ffi.cast(_cast[self.obj_type], self)
end

core_object_t = ffi.metatype(t_name, { __index = Object })

-- dnsjit.core.object.pcap (3),
-- dnsjit.core.object.ether (3),
-- dnsjit.core.object.null (3),
-- dnsjit.core.object.loop (3),
-- dnsjit.core.object.linuxsll (3),
-- dnsjit.core.object.ieee802 (3),
-- dnsjit.core.object.gre (3),
-- dnsjit.core.object.ip (3),
-- dnsjit.core.object.ip6 (3),
-- dnsjit.core.object.icmp (3),
-- dnsjit.core.object.icmp6 (3),
-- dnsjit.core.object.udp (3),
-- dnsjit.core.object.tcp (3),
-- dnsjit.core.object.packet (3),
-- dnsjit.core.object.dns (3)
return Object

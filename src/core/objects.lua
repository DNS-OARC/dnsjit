-- Copyright (c) 2018-2019, OARC, Inc.
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

-- dnsjit.core.objects
-- Easy way to import all objects
--   require("dnsjit.core.objects")
--
-- Helper module to require all available objects, returns what
-- .I dnsjit.core.object
-- returned so that constants like object types can be used.
module(...,package.seeall)

local object = require("dnsjit.core.object")
require("dnsjit.core.object.pcap")
require("dnsjit.core.object.ether")
require("dnsjit.core.object.null")
require("dnsjit.core.object.loop")
require("dnsjit.core.object.linuxsll")
require("dnsjit.core.object.ieee802")
require("dnsjit.core.object.gre")
require("dnsjit.core.object.ip")
require("dnsjit.core.object.ip6")
require("dnsjit.core.object.icmp")
require("dnsjit.core.object.icmp6")
require("dnsjit.core.object.udp")
require("dnsjit.core.object.tcp")
require("dnsjit.core.object.payload")
require("dnsjit.core.object.dns")

-- dnsjit.core.object (3),
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
-- dnsjit.core.object.payload (3),
-- dnsjit.core.object.dns (3)
return object

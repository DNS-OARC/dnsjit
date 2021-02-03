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

-- dnsjit.core.object.pcap
-- Container of a packet found in a PCAP
--
-- Container of a PCAP packet which contains information both from the PCAP
-- itself and the
-- .I pcap_pkthdr
-- object receied for each packet in the PCAP.
-- .SS Attributes
-- .TP
-- snaplen
-- Max length saved portion of each packet.
-- .TP
-- linktype
-- Data link type for the PCAP.
-- .TP
-- ts
-- Time stamp of this packet.
-- .TP
-- caplen
-- Length of portion present.
-- .TP
-- len
-- Length of this packet (off wire).
-- .TP
-- bytes
-- A pointer to the packet.
-- .TP
-- is_swapped
-- Indicate if the byte order of the PCAP is different then the host.
-- This is used in, for example, the Layer filter to correctly parse null
-- objects since they are stored in the capturers host byte order.
module(...,package.seeall)

require("dnsjit.core.object.pcap_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_pcap_t"
local core_object_pcap_t
local Pcap = {}

-- Return the textual type of the object.
function Pcap:type()
    return "pcap"
end

-- Return the previous object.
function Pcap:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Pcap:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Pcap:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Pcap:copy()
    return C.core_object_pcap_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Pcap:free()
    C.core_object_pcap_free(self)
end

core_object_pcap_t = ffi.metatype(t_name, { __index = Pcap })

-- dnsjit.core.object (3),
-- dnsjit.input.pcap (3),
-- dnsjit.input.fpcap (3),
-- dnsjit.input.mmpcap (3),
-- dnsjit.filter.layer (3),
-- dnsjit.output.pcap (3)
return Pcap

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

-- dnsjit.core.object.payload
-- Application data payload
--
-- Payload object contains the data carried by the underlying transport
-- protocol.
-- Payload is usually at the top of the object chain after parsing with,
-- for example,
-- .IR dnsjit.filter.layer .
-- .SS Attributes
-- .TP
-- payload
-- A pointer to the payload.
-- .TP
-- len
-- The length of the payload.
-- .TP
-- padding
-- The length of padding in the underlying packet.
module(...,package.seeall)

require("dnsjit.core.object.payload_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_payload_t"
local core_object_payload_t
local Payload = {}

-- Return the textual type of the object.
function Payload:type()
    return "payload"
end

-- Return the previous object.
function Payload:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Payload:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Payload:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Payload:copy()
    return C.core_object_payload_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Payload:free()
    C.core_object_payload_free(self)
end

core_object_payload_t = ffi.metatype(t_name, { __index = Payload })

-- dnsjit.core.object (3),
-- dnsjit.core.object.udp (3),
-- dnsjit.core.object.tcp (3),
-- dnsjit.filter.layer (3)
return Payload

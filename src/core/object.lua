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
require("dnsjit.core.object.packet")
require("dnsjit.core.object.dns")
local ffi = require("ffi")

local t_name = "core_object_t"
local core_object_t
local Object = {
    CORE_OBJECT_NONE = 0,
    CORE_OBJECT_PACKET = 1,
    CORE_OBJECT_DNS = 2,
}

-- Return the textual type of the object.
function Object:type()
    if self.obj_type == Object.CORE_OBJECT_PACKET then
        return "packet"
    elseif self.obj_type == Object.CORE_OBJECT_DNS then
        return "dns"
    end
    return "none"
end

-- Return the previous object.
function Object:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Object:cast()
    if self.obj_type == Object.CORE_OBJECT_PACKET then
        return ffi.cast("core_object_packet_t*", self)
    elseif self.obj_type == Object.CORE_OBJECT_DNS then
        return ffi.cast("core_object_dns_t*", self)
    end
end

core_object_t = ffi.metatype(t_name, { __index = Object })

-- dnsjit.core.object.dns (3),
-- dnsjit.core.object.packet (3)
return Object

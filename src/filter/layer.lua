-- Copyright (c) 2018-2022, OARC, Inc.
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

-- dnsjit.filter.layer
-- Parse the ether/IP stack
--   local filter = require("dnsjit.filter.layer").new()
--
-- Parse the ether/IP stack of the received objects and send the top most
-- object to the receivers.
-- Objects are chained which each layer in the stack with the top most first.
-- Currently supports input
-- .IR dnsjit.core.object.pcap .
module(...,package.seeall)

require("dnsjit.filter.layer_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "filter_layer_t"
local filter_layer_t = ffi.typeof(t_name)
local Layer = {}

-- Create a new Layer filter.
function Layer.new()
    local self = {
        _receiver = nil,
        obj = filter_layer_t(),
    }
    C.filter_layer_init(self.obj)
    ffi.gc(self.obj, C.filter_layer_destroy)
    return setmetatable(self, { __index = Layer })
end

-- Return the Log object to control logging of this instance or module.
function Layer:log()
    if self == nil then
        return C.filter_layer_log()
    end
    return self.obj._log
end

-- Return the C functions and context for receiving objects.
function Layer:receive()
    return C.filter_layer_receiver(), self.obj
end

-- Set the receiver to pass objects to.
function Layer:receiver(o)
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

-- Return the C functions and context for producing objects.
function Layer:produce()
    return C.filter_layer_producer(self.obj), self.obj
end

-- Set the producer to get objects from.
function Layer:producer(o)
    self.obj.prod, self.obj.prod_ctx = o:produce()
    self._producer = o
end

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
-- dnsjit.core.object.payload (3)
return Layer

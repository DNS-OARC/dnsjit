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

-- dnsjit.output.tlscli
-- Simple TLS client
--   local output = require("dnsjit.output.tlscli").new("127.0.0.1", "853")
--
-- Simple TLS client that attempts to do a TLS handshake (without
-- certificate verification). It behaves the same way as tcpcli, except all
-- the data is sent over the encrypted channel.
-- .SS Attributes
-- .TP
-- timeout
-- A
-- .I core.timespec
-- that is used when producing objects.
module(...,package.seeall)

require("dnsjit.output.tlscli_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_tlscli_t"
local output_tlscli_t = ffi.typeof(t_name)
local Tlscli = {}

-- Create a new Tlscli output.
function Tlscli.new()
    local self = {
        obj = output_tlscli_t(),
    }
    C.output_tlscli_init(self.obj)
    ffi.gc(self.obj, C.output_tlscli_destroy)
    return setmetatable(self, { __index = Tlscli })
end

-- Set the timeout when producing objects.
function Tlscli:timeout(seconds, nanoseconds)
    self.obj.timeout.sec = seconds
    self.obj.timeout.nsec = nanoseconds
end

-- Connect to the
-- .I host
-- and
-- .I port
-- , perform a TLS handshake and return 0 if successful.
function Tlscli:connect(host, port)
    return C.output_tlscli_connect(self.obj, host, port)
end

-- Return the C functions and context for receiving objects, these objects
-- will be sent.
function Tlscli:receive()
    return C.output_tlscli_receiver(self.obj), self.obj
end

-- Return the C functions and context for producing objects, these objects
-- are received.
-- The producer will wait for data and if timed out (see
-- .IR timeout )
-- it will return a payload object with length zero.
-- If a timeout happens during during the first stage, getting the length, it
-- will fail and return nil.
-- Additional calls will continue retrieving the payload.
-- The producer returns nil on error.
function Tlscli:produce()
    return C.output_tlscli_producer(self.obj), self.obj
end

-- Return the number of "packets" sent, actually the number of completely sent
-- payloads.
function Tlscli:packets()
    return tonumber(self.obj.pkts)
end

-- Return the number of "packets" received, actually the number of completely
-- received DNS messages.
function Tlscli:received()
    return tonumber(self.obj.pkts_recv)
end

-- Return the number of errors when sending.
function Tlscli:errors()
    return tonumber(self.obj.errs)
end

return Tlscli

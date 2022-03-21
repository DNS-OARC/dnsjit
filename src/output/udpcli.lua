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

-- dnsjit.output.udpcli
-- Simple and dumb UDP DNS client
--   local output = require("dnsjit.output.udpcli").new("127.0.0.1", "53")
--
-- Simple and rather dumb DNS client that takes any payload you give it and
-- sends the full payload over UDP.
-- .SS Attributes
-- .TP
-- timeout
-- A
-- .I core.timespec
-- that is used when producing objects.
module(...,package.seeall)

require("dnsjit.output.udpcli_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_udpcli_t"
local output_udpcli_t = ffi.typeof(t_name)
local Udpcli = {}

-- Create a new Udpcli output.
function Udpcli.new()
    local self = {
        obj = output_udpcli_t(),
    }
    C.output_udpcli_init(self.obj)
    ffi.gc(self.obj, C.output_udpcli_destroy)
    return setmetatable(self, { __index = Udpcli })
end

-- Set the timeout when producing objects.
function Udpcli:timeout(seconds, nanoseconds)
    self.obj.timeout.sec = seconds
    self.obj.timeout.nsec = nanoseconds
end

-- Connect to the
-- .I host
-- and
-- .I port
-- and return 0 if successful.
function Udpcli:connect(host, port)
    return C.output_udpcli_connect(self.obj, host, port)
end

-- Enable (true) or disable (false) nonblocking mode and
-- return 0 if successful, if
-- .I bool
-- is not specified then return if nonblocking mode is on (true) or off (false).
function Udpcli:nonblocking(bool)
    if bool == nil then
        if C.output_udpcli_nonblocking(self.obj) == 1 then
            return true
        end
        return false
    elseif bool == true then
        return C.output_udpcli_set_nonblocking(self.obj, 1)
    else
        return C.output_udpcli_set_nonblocking(self.obj, 0)
    end
end

-- Return the C functions and context for receiving objects, these objects
-- will be sent.
function Udpcli:receive()
    return C.output_udpcli_receiver(self.obj), self.obj
end

-- Return the C functions and context for producing objects, these objects
-- are received.
-- If nonblocking mode is enabled the producer will return a payload object
-- with length zero if there was nothing to receive.
-- If nonblocking mode is disabled the producer will wait for data and if
-- timed out (see
-- .IR timeout )
-- it will return a payload object with length zero.
-- The producer returns nil on error.
function Udpcli:produce()
    return C.output_udpcli_producer(self.obj), self.obj
end

-- Return the number of "packets" sent, actually the number of completely sent
-- payloads.
function Udpcli:packets()
    return tonumber(self.obj.pkts)
end

-- Return the number of "packets" received, actually the number of successful
-- calls to
-- .IR recvfrom (2)
-- that returned data.
function Udpcli:received()
    return tonumber(self.obj.pkts_recv)
end

-- Return the number of errors when sending or receiving.
function Udpcli:errors()
    return tonumber(self.obj.errs)
end

return Udpcli

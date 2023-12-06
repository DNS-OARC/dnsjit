-- Copyright (c) 2018-2023, OARC, Inc.
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

-- dnsjit.output.dnscli
-- DNS aware UDP/TCP/TLS client
--   local dnscli = require("dnsjit.output.dnscli")
-- .SS UDP Receiver Chain
--   local output = dnscli.new(dnscli.UDP)
--   output:connect("127.0.0.1", "53")
--   input:receiver(output)
-- .SS TCP Nonblocking
--   local output = dnscli.new(dnscli.TCP + dnscli.NONBLOCKING)
--   output:send(object)
--
-- The DNS client can a
-- .I core.object.dns
-- or a
-- .I core.object.payload
-- object via the receiver interface or using
-- .I send()
-- and send it as DNS query after which it can receive the response by using
-- the producer interface.
-- If the object being sent is a
-- .I core.object.dns
-- then it will look at
-- .I includes_dnslen
-- attribute and depending on the protocol it will disregard, include or send
-- the DNS length as an extra packet.
-- If the object being sent is a
-- .I core.object.payload
-- then no special handling will be done and it will be sent as is.
-- When receiving responses the producer interface will generate
-- .I core.object.payload
-- objects which may include the DNS length depending on the protocol used and
-- must be handled by the caller.
-- .SS MODES
-- These transport modes and options are available when creating a new Dnscli
-- output.
-- .TP
-- UDP
-- Create an output using UDP.
-- .TP
-- TCP
-- Create an output using TCP.
-- .TP
-- TLS
-- Create an output using TCP and encrypt it with TLS.
-- .TP
-- NONBLOCKING
-- Make the client nonblocking, see
-- .I send()
-- and
-- .IR produce() .
module(...,package.seeall)

require("dnsjit.output.dnscli_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_dnscli_t"
local output_dnscli_t = ffi.typeof(t_name)
local Dnscli = {
    NONBLOCKING = 0x1,
    UDP = 0x10,
    TCP = 0x20,
    TLS = 0x30,
}

-- Create a new Dnscli output.
function Dnscli.new(mode)
    local self = {
        obj = output_dnscli_t(),
    }
    C.output_dnscli_init(self.obj, mode)
    ffi.gc(self.obj, C.output_dnscli_destroy)
    return setmetatable(self, { __index = Dnscli })
end

-- Set or return the timeout used for sending and reciving, must be used before
-- .IR connect() .
function Dnscli:timeout(seconds, nanoseconds)
    if seconds == nil and nanoseconds == nil then
        return self.obj.timeout
    end
    if nanoseconds == nil then
        nanoseconds = 0
    end
    self.obj.timeout.sec = seconds
    self.obj.timeout.nsec = nanoseconds
end

-- Connect to the
-- .I host
-- and
-- .I port
-- and return 0 if successful.
function Dnscli:connect(host, port)
    return C.output_dnscli_connect(self.obj, host, port)
end

-- Return if nonblocking mode is on (true) or off (false).
function Dnscli:nonblocking()
    if self.obj.nonblocking == 1 then
        return true
    end
    return false
end

-- Send an object and optionally continue sending after
-- .I sent
-- bytes.
-- Unlike the receive interface this function lets you know if the sending was
-- successful or not which might be needed on nonblocking connections.
-- Returns -2 on error, -1 if interrupted, timed out or unable to send due to
-- nonblocking, or the number of bytes sent.
-- .B Note
-- the counters for sent, received, errors and timeouts are not affected by
-- this function.
function Dnscli:send(object, sent)
    if sent == nil then
        sent = 0
    end
    return C.output_dnscli_send(self.obj, object, sent)
end

-- Return the C functions and context for receiving objects, these objects
-- will be sent.
function Dnscli:receive()
    return C.output_dnscli_receiver(self.obj), self.obj
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
function Dnscli:produce()
    return C.output_dnscli_producer(self.obj), self.obj
end

-- Return the number of "packets" sent, actually the number of completely sent
-- payloads.
function Dnscli:packets()
    return tonumber(self.obj.pkts)
end

-- Return the number of "packets" received, actually the number of successful
-- calls to
-- .IR recvfrom (2)
-- that returned data.
function Dnscli:received()
    return tonumber(self.obj.pkts_recv)
end

-- Return the number of errors when sending or receiving.
function Dnscli:errors()
    return tonumber(self.obj.errs)
end

-- Return the number of timeouts when sending or receiving.
function Dnscli:timeouts()
    return tonumber(self.obj.timeouts)
end

-- core.object.dns (3),
-- core.object.payload (3),
-- core.timespec (3)
return Dnscli

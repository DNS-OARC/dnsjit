-- Copyright (c) 2018-2019, CZ.NIC, z.s.p.o.
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

-- dnsjit.output.dnssim
-- Simulate independent DNS clients over various transports
--   TODO
--
-- Output module for simulating traffic from huge number of independent,
-- individual DNS clients. Uses libuv for asynchronous communication. There
-- may only be a single dnssim in a thread. Use dnsjit.core.thread to have
-- multiple dnssim instances.
module(...,package.seeall)

require("dnsjit.output.dnssim_h")
local bit = require("bit")
local object = require("dnsjit.core.objects")
local ffi = require("ffi")
local C = ffi.C

local DnsSim = {}

-- Create a new DnsSim output for up to max_clients.
function DnsSim.new(max_clients)
    local self = {
        obj = C.output_dnssim_new(max_clients),
        clients = {},
        i_client = 0,
    }
    ffi.gc(self.obj, C.output_dnssim_free)
    return setmetatable(self, { __index = DnsSim })
end

-- Return the Log object to control logging of this instance or module.
function DnsSim:log()
    if self == nil then
        return C.output_dnssim_log()
    end
    return self.obj._log
end

-- Set the transport to UDP (without any TCP fallback).
function DnsSim:udp_only()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY)
end

-- Set the preferred transport to UDP. This transport falls back to TCP
-- for individual queries if TC bit is set in received answer.
function DnsSim:udp()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_UDP)
    self.obj.transport = "OUTPUT_DNSSIM_TRANSPORT_UDP"
end

-- Set the transport to TCP.
function DnsSim:tcp()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_TCP)
    self.obj.transport = "OUTPUT_DNSSIM_TRANSPORT_TCP"
end

-- Set the transport to TLS.
function DnsSim:tls()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_TLS)
end

-- Set this to true if dnssim should free the memory of passed-in objects (useful
-- when using copy() to pass objects from different thread).
function DnsSim:free_after_use(free_after_use)
    self.obj.free_after_use = free_after_use
end

-- Return the C function and context for receiving objects.
function DnsSim:receive()
    local receive = C.output_dnssim_receiver()
    local i = 1
    function lua_recv(ctx, obj)
        if obj == nil then
            self.obj.discarded = self.obj.discarded + 1
            self.obj._log:warning("packet discarded (no data)")
            return
        end
        local pkt = ffi.cast("core_object_t*", obj)
        repeat
            if pkt == nil then
                self.obj.discarded = self.obj.discarded + 1
                self.obj._log:warning("packet discarded (missing ip/ip6 object)")
                return
            end
            if pkt.obj_type == object.IP or pkt.obj_type == object.IP6 then
                -- assign unique client number based on IP
                local ip = pkt:cast()
                local client = self.clients[ip:source()]
                if client == nil then
                    self.clients[ip:source()] = self.i_client
                    client = self.i_client
                    self.i_client = self.i_client + 1
                end
                self.obj._log:debug("client(lua): "..client)

                -- put the client number into dst IP
                ip.dst[3] = bit.band(client, 0xff)
                ip.dst[2] = bit.rshift(bit.band(client, 0xff00), 8)
                ip.dst[1] = bit.rshift(bit.band(client, 0xff0000), 16)
                ip.dst[0] = bit.rshift(bit.band(client, 0xff000000), 24)

                return receive(ctx, obj)
            end
            pkt = pkt.obj_prev
        until(false)
    end
    return lua_recv, self.obj
end

-- Set the target server where queries will be sent to. Returns 0 on success.
function DnsSim:target(ip, port)
    nport = tonumber(port)
    if nport == nil then
        self.obj._log:critical("invalid port: "..port)
        return -1
    end
    if nport <= 0 or nport > 65535 then
        self.obj._log:critical("invalid port number: "..nport)
        return -1
    end
    return C.output_dnssim_target(self.obj, ip, nport)
end

-- Specify source address for sending queries. Can be set multiple times. Adresses
-- are selected round-robin when sending.
function DnsSim:bind(ip)
    return C.output_dnssim_bind(self.obj, ip)
end

-- Run the libuv loop once without blocking when there is no I/O. This
-- should be called repeatedly until 0 is returned and no more data
-- is expected to be received by DnsSim.
function DnsSim:run_nowait()
    return C.output_dnssim_run_nowait(self.obj)
end

-- Number of input packets discarded due to various reasons.
-- To investigate causes, run with increased logging level.
function DnsSim:discarded()
    return tonumber(self.obj.discarded)
end

-- Number of valid requests (input packets) processed.
function DnsSim:total()
    local total = 0
    for i = 0, self.i_client do
        local n = tonumber(self.obj.client_arr[i].req_total)
        if n ~= nil then
            total = total + n
        end
    end
    return total
end

-- Number of requests that received an answer
function DnsSim:answered()
    local answered = 0
    for i = 0, self.i_client do
        local n = tonumber(self.obj.client_arr[i].req_answered)
        if n ~= nil then
            answered = answered + n
        end
    end
    return answered
end

-- Number of requests that received a NOERROR response
function DnsSim:noerror()
    local noerror = 0
    for i = 0, self.i_client do
        local n = tonumber(self.obj.client_arr[i].req_noerror)
        if n ~= nil then
            noerror = noerror + n
        end
    end
    return noerror
end

-- Export the results to a JSON file
function DnsSim:export(filename)
    local file = io.open(filename, "w")
    if file == nil then
        -- TODO log error
        return
    end

    file:write("{\n")
    file:write('"discarded": ', self:discarded(), ', \n')
    file:write('"total": ', self:total(), ', \n')
    file:write('"answered": ', self:answered(), ', \n')
    file:write('"noerror": ', self:noerror(), ', \n')
    file:write("}")
    file:close()
end

return DnsSim

-- Copyright (c) 2019 CZ.NIC, z.s.p.o.
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

-- dnsjit.filter.dnssim
-- Prepare packets for dnssim output layer and optionally split them
-- among multiple receivers in a client-aware (source IP) manner.
--   local filter = require("dnsjit.filter.dnssim").new()
--   filter.receiver(...)
--   filter.receiver(...)
--   filter.receiver(...)
--   input.receiver(filter)
--
-- Filter for preparing packets for dnssim output component.
module(...,package.seeall)

require("dnsjit.filter.dnssim_h")
local bit = require("bit")
local object = require("dnsjit.core.objects")
local ffi = require("ffi")
local C = ffi.C

local t_name = "filter_dnssim_t"
local filter_dnssim_t = ffi.typeof(t_name)
local DnsSim = {}

-- Create a new DnsSim filter.
function DnsSim.new()
    local self = {
        receivers = {},
        obj = filter_dnssim_t(),
        clients = {},
        i_receiver = 1,
    }
    C.filter_dnssim_init(self.obj)
    ffi.gc(self.obj, C.filter_dnssim_destroy)
    return setmetatable(self, { __index = DnsSim })
end

-- Return the Log object to control logging of this instance or module.
function DnsSim:log()
    if self == nil then
        return C.filter_dnssim_log()
    end
    return self.obj._log
end

-- Return the C functions and context for receiving objects.
function DnsSim:receive()
    --local receive = C.filter_dnssim_receiver(self.obj)
    if #self.receivers < 1 then
        self.obj._log:fatal("no receiver(s) set")
    end
    local function lua_recv(_, obj)
        if obj == nil then
            self.obj.discarded = self.obj.discarded + 1
            self.obj._log:warning("packet discarded (no data)")
            return
        end
        local pkt = ffi.cast("core_object_t*", obj)
        repeat
            if pkt == nil then
                self.obj.discarded = self.obj.discarded + 1
                self.obj._log:warning("packet discarded (missing ip6 object)")
                return
            end
            if pkt.obj_type == object.IP6 then
                -- get client info from IP
                local ip6 = pkt:cast()
                -- IPv6 has to differ in least significant 4 octets
                local addr_hash = (
                    ip6.src[15] +
                    bit.lshift(ip6.src[14], 8) +
                    bit.lshift(ip6.src[13], 16) +
                    bit.lshift(ip6.src[12], 32))
                local client_data = self.clients[addr_hash]
                local client, receiver
                if client_data == nil then
                    receiver = self.receivers[self.i_receiver]
                    client = {}
                    client[3] = bit.band(receiver.i_client, 0xff)
                    client[2] = bit.rshift(bit.band(receiver.i_client, 0xff00), 8)
                    client[1] = bit.rshift(bit.band(receiver.i_client, 0xff0000), 16)
                    client[0] = bit.rshift(bit.band(receiver.i_client, 0xff000000), 24)
                    -- TODO: support other than roundrobin distribution
                    self.clients[addr_hash] = {client, receiver}
                    receiver.i_client = receiver.i_client + 1
                    self.i_receiver = self.i_receiver % #self.receivers + 1
                else
                    client = client_data[1]
                    receiver = client_data[2]
                end

                -- put the client number into dst IP
                ip6.dst[3] = client[3]
                ip6.dst[2] = client[2]
                ip6.dst[1] = client[1]
                ip6.dst[0] = client[0]

                return receiver.recv(receiver.ctx, obj)
            end
            pkt = pkt.obj_prev
        until(false)
    end
    return lua_recv, self.obj
end

-- Set the receiver to pass objects to, this can be called multiple times to
-- set addtional receivers.
function DnsSim:receiver(o)
    local recv, ctx = o:receive()
    table.insert(self.receivers, {recv=recv, ctx=ctx, i_client=0})
end

return DnsSim

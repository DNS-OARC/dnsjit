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

module(...,package.seeall)

local log = require("dnsjit.core.log")
require("dnsjit.input.pcap_h")
local ffi = require("ffi")
local C = ffi.C

local type = "input_pcap_t"
local struct
local mt = {
    __gc = function(self)
        if ffi.istype(type, self) then
            C.input_pcap_destroy(self)
        end
    end,
    __index = {
        new = function()
            local self = struct()
            if not self then
                error("oom")
            end
            if ffi.istype(type, self) then
                C.input_pcap_init(self)
                return self
            end
        end
    }
}
struct = ffi.metatype(type, mt)

local Pcap = {}

function Pcap.new()
    local o = struct.new()
    local log = log.new(o.log)
    log:debug("new()")
    return setmetatable({
        _ = o,
        _receiver = nil,
        log = log,
    }, {__index = Pcap})
end

function Pcap:receiver(o)
    self.log:debug("receiver()")
    self._.recv, self._.robj = o:receive()
    self._receiver = o
end

function bool2int(bool)
    if bool == true then
        return 1
    elseif bool == false then
        return 0
    end
end

function int2bool(int)
    if int == 0 then
        return false
    end
    return true
end

function zero2none(int)
    if not int == 0 then
        return int
    end
end

function Pcap:only_queries(bool)
    if bool == nil then
        return int2bool(self._.only_queries)
    end
    local b = bool2int(bool)
    if b == nil then
        return 1
    end
    self._.only_queries = b
end

function Pcap:snapshot()
    return C.pcap_thread_snapshot(self._.pt)
end

function Pcap:snaplen(len)
    if len == nil then
        return C.pcap_thread_snaplen(self._.pt)
    end
    return zero2none(C.pcap_thread_set_snaplen(self._.pt, len))
end

function Pcap:promiscuous(bool)
    if bool == nil then
        return int2bool(C.pcap_thread_promiscuous(self._.pt))
    end
    local b = bool2int(bool)
    if b == nil then
        return 1
    end
    return zero2none(C.pcap_thread_set_promiscuous(self._.pt, b))
end

function Pcap:monitor()
    if bool == nil then
        return int2bool(C.pcap_thread_monitor(self._.pt))
    end
    local b = bool2int(bool)
    if b == nil then
        return 1
    end
    return zero2none(C.pcap_thread_set_monitor(self._.pt, b))
end

function Pcap:timeout(ms)
    if ms == nil then
        return C.pcap_thread_timeout(self._.pt)
    end
    return zero2none(C.pcap_thread_set_timeout(self._.pt, ms))
end

function Pcap:buffer_size(size)
    if size == nil then
        return C.pcap_thread_buffer_size(self._.pt)
    end
    return zero2none(C.pcap_thread_set_buffer_size(self._.pt, size))
end

function Pcap:immediate_mode()
    if bool == nil then
        return int2bool(C.pcap_thread_immediate_mode(self._.pt))
    end
    local b = bool2int(bool)
    if b == nil then
        return 1
    end
    return zero2none(C.pcap_thread_set_immediate_mode(self._.pt, b))
end

function Pcap:filter(pf)
    if pf == nil then
        return ffi.string(C.pcap_thread_filter(self._.pt))
    elseif pf == false then
        return zero2none(C.pcap_thread_clear_filter(self._.pt))
    end
    return zero2none(C.pcap_thread_set_filter(self._.pt, pf, string.len(pf)))
end

function Pcap:filter_errno()
    return C.pcap_thread_filter_errno(self._.pt)
end

function Pcap:filter_optimize()
    if bool == nil then
        return int2bool(C.pcap_thread_filter_optimize(self._.pt))
    end
    local b = bool2int(bool)
    if b == nil then
        return 1
    end
    return zero2none(C.pcap_thread_set_filter_optimize(self._.pt, b))
end

function Pcap:filter_netmask(netmask)
    if netmask == nil then
        return C.pcap_thread_filter_netmask(self._.pt)
    end
    return zero2none(C.pcap_thread_set_filter_netmask(self._.pt, netmask))
end

function Pcap:open(device)
    return C.input_pcap_open(self._, device)
end

function Pcap:open_offline(file)
    return C.input_pcap_open_offline(self._, file)
end

function Pcap:run()
    return C.input_pcap_run(self._)
end

function Pcap:next()
    return C.input_pcap_next(self._)
end

function Pcap:errbuf()
    return C.input_pcap_errbuf(self._)
end

function Pcap:strerr(err)
    if err == nil then
        return C.input_pcap_strerr(self._.err)
    end
    return C.input_pcap_strerr(err)
end

function Pcap:start_time()
    return tonumber(self._.ts.sec), tonumber(self._.ts.nsec)
end

function Pcap:end_time()
    return tonumber(self._.te.sec), tonumber(self._.te.nsec)
end

function Pcap:packets()
    return tonumber(self._.pkts)
end

function Pcap:dropped()
    return tonumber(self._.drop)
end

function Pcap:ignored()
    return tonumber(self._.ignore)
end

function Pcap:queries()
    return tonumber(self._.queries)
end

return Pcap

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

-- dnsjit.input.lua
-- Read input from an interface or PCAP file
--   local input = require("dnsjit.input.pcap").new()
--   input:open_offline("file.pcap")
--   input:receiver(filter_or_output)
--   input:run()
--
-- Input module for reading input from interfaces and PCAP files.
module(...,package.seeall)

local ch = require("dnsjit.core.chelpers")
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

-- Create a new Pcap input.
function Pcap.new()
    local o = struct.new()
    return setmetatable({
        _ = o,
        _receiver = nil,
    }, {__index = Pcap})
end

-- Return the Log object to control logging of this instance or module.
function Pcap:log()
    if self == nil then
        return C.input_pcap_log()
    end
    return self._._log
end

-- Set the receiver to pass queries to.
function Pcap:receiver(o)
    self._._log:debug("receiver()")
    self._.recv, self._.robj = o:receive()
    self._receiver = o
end

-- Only pass DNS queries, the DNS header will be parsed and QR must be 0.
function Pcap:only_queries(bool)
    if bool == nil then
        return ch.i2b(self._.only_queries)
    end
    local b = ch.b2i(bool)
    if b == nil then
        return 1
    end
    self._.only_queries = b
end

-- Return the snaphot length, see
-- .BR pcap_snapshot (3pcap)
-- for more information.
function Pcap:snapshot()
    return C.pcap_thread_snapshot(self._.pt)
end

-- Set the number of bytes to try and capture, use
-- .BR snaphot ()
-- too see how many bytes are actually captured.
-- If
-- .I len
-- is not specified then return the number of bytes that was previously
-- set by this function.
function Pcap:snaplen(len)
    if len == nil then
        return C.pcap_thread_snaplen(self._.pt)
    end
    return ch.z2n(C.pcap_thread_set_snaplen(self._.pt, len))
end

-- Enable (true) or disable (false) promiscuous mode, if
-- .I bool
-- is not specified then return if promiscuous mode is on (true) or off (false).
-- See
-- .BR pcap (3pcap)
-- for more information.
function Pcap:promiscuous(bool)
    if bool == nil then
        return ch.i2b(C.pcap_thread_promiscuous(self._.pt))
    end
    local b = ch.b2i(bool)
    if b == nil then
        return 1
    end
    return ch.z2n(C.pcap_thread_set_promiscuous(self._.pt, b))
end

-- Enable (true) or disable (false) monitor mode, if
-- .I bool
-- is not specified then return if monitor mode is on (true) or off (false).
-- See
-- .BR pcap (3pcap)
-- for more information.
function Pcap:monitor(bool)
    if bool == nil then
        return ch.i2b(C.pcap_thread_monitor(self._.pt))
    end
    local b = ch.b2i(bool)
    if b == nil then
        return 1
    end
    return ch.z2n(C.pcap_thread_set_monitor(self._.pt, b))
end

-- Set the timeout in milliseconds, if
-- .I ms
-- is not specified then return the current timeout.
-- See
-- .BR pcap_set_timeout (3pcap)
-- for more information.
function Pcap:timeout(ms)
    if ms == nil then
        return C.pcap_thread_timeout(self._.pt)
    end
    return ch.z2n(C.pcap_thread_set_timeout(self._.pt, ms))
end

-- Set the buffer size, if
-- .I size
-- is not specified then return the current buffer size.
-- See
-- .BR pcap_set_buffer_size (3pcap)
-- for more information.
function Pcap:buffer_size(size)
    if size == nil then
        return C.pcap_thread_buffer_size(self._.pt)
    end
    return ch.z2n(C.pcap_thread_set_buffer_size(self._.pt, size))
end

-- Enable (true) or disable (false) immediate mode, if
-- .I bool
-- is not specified then return if immediate mode is on (true) or off (false).
-- May have no effect depending on libpcap version.
-- See
-- .BR pcap_set_immediate_mode (3pcap)
-- for more information.
function Pcap:immediate_mode()
    if bool == nil then
        return ch.i2b(C.pcap_thread_immediate_mode(self._.pt))
    end
    local b = ch.b2i(bool)
    if b == nil then
        return 1
    end
    return ch.z2n(C.pcap_thread_set_immediate_mode(self._.pt, b))
end

-- Set the PCAP packet filter to use, if
-- .I pf
-- is not specified then return the current packet filter in use.
-- See
-- .BR pcap-filter (3pcap)
-- for more information.
function Pcap:filter(pf)
    if pf == nil then
        return ffi.string(C.pcap_thread_filter(self._.pt))
    elseif pf == false then
        return ch.z2n(C.pcap_thread_clear_filter(self._.pt))
    end
    return ch.z2n(C.pcap_thread_set_filter(self._.pt, pf, string.len(pf)))
end

-- Return the error number return from libpcap while parsing the packet filter.
function Pcap:filter_errno()
    return C.pcap_thread_filter_errno(self._.pt)
end

-- Enable (true) or disable (false) packet filter optimizing, if
-- .I bool
-- is not specified then return if packet filter optimizing is on (true) or off (false).
-- See
-- .BR pcap_compile (3pcap)
-- for more information.
function Pcap:filter_optimize(bool)
    if bool == nil then
        return ch.i2b(C.pcap_thread_filter_optimize(self._.pt))
    end
    local b = ch.b2i(bool)
    if b == nil then
        return 1
    end
    return ch.z2n(C.pcap_thread_set_filter_optimize(self._.pt, b))
end

-- Set the network mask to give when compiling the packet filter, if
-- .I netmask
-- is not specified then return the current network mask.
-- See
-- .BR pcap_compile (3pcap)
-- for more information.
function Pcap:filter_netmask(netmask)
    if netmask == nil then
        return C.pcap_thread_filter_netmask(self._.pt)
    end
    return ch.z2n(C.pcap_thread_set_filter_netmask(self._.pt, netmask))
end

-- Open an interface device for capturing, can be given multiple times to
-- open additional interfaces.
function Pcap:open(device)
    return ch.z2n(C.input_pcap_open(self._, device))
end

-- Open a PCAP file for processing, can be given multiple times to
-- open additional files.
function Pcap:open_offline(file)
    return ch.z2n(C.input_pcap_open_offline(self._, file))
end

-- Start processing packet from opened devices and PCAP files.
function Pcap:run()
    return ch.z2n(C.input_pcap_run(self._))
end

-- Process one packet from the opened devices and PCAP files, the opened
-- sources are processed as a round robin list.
function Pcap:next()
    return ch.z2n(C.input_pcap_next(self._))
end

-- Return the last error as a string that came from libpcap functions
-- that takes an error buffer.
-- See for example
-- .BR pcap_open_offline (3pcap).
function Pcap:errbuf()
    return ffi.string(C.input_pcap_errbuf(self._))
end

-- Return the error
-- .I err
-- as a string or if not specified the last error.
function Pcap:strerr(err)
    if err == nil then
        return ffi.string(C.input_pcap_strerr(self._.err))
    end
    return ffi.string(C.input_pcap_strerr(err))
end

-- Return the seconds and nanoseconds (as a list) of the start time for
-- .BR Pcap:run() .
function Pcap:start_time()
    return tonumber(self._.ts.sec), tonumber(self._.ts.nsec)
end

-- Return the seconds and nanoseconds (as a list) of the stop time for
-- .BR Pcap:run() .
function Pcap:end_time()
    return tonumber(self._.te.sec), tonumber(self._.te.nsec)
end

-- Return the number of packets seen.
function Pcap:packets()
    return tonumber(self._.pkts)
end

-- Return the number of packets dropped.
function Pcap:dropped()
    return tonumber(self._.drop)
end

-- Return the number of packets ignored as a result of only processing queries.
-- See
-- .BR Pcap:only_queries() .
function Pcap:ignored()
    return tonumber(self._.ignore)
end

-- Return the number of queries seen, see
-- .BR Pcap:only_queries() .
function Pcap:queries()
    return tonumber(self._.queries)
end

return Pcap

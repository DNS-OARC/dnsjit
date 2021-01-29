-- Copyright (c) 2018-2021, CZ.NIC, z.s.p.o.
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
--   output = require("dnsjit.output.dnssim").new()
-- .SS Usage
--   output:udp()
--   output:target("::1", 53)
--   recv, rctx = output:receive()
--   -- pass in objects using recv(rctx, obj)
--   -- repeatedly call output:run_nowait() until it returns 0
-- .SS DNS-over-TLS example configuration
--   output:tls("NORMAL:-VERS-ALL:+VERS-TLS1.3")  -- enforce TLS 1.3
-- .SS DNS-over-HTTPS/2 example configuration
--   output:https2({ method = "POST", uri_path = "/doh" })
--
-- Output module for simulating traffic from huge number of independent,
-- individual DNS clients.
-- Uses libuv for asynchronous communication.
-- There may only be a single DnsSim in a thread.
-- Use
-- .I dnsjit.core.thread
-- to have multiple DnsSim instances.
-- .P
-- With proper use of this component, it is possible to simulate hundreds of
-- thousands of clients when using a high-performance server.
-- This also applies for state-full transports.
-- The complete set-up is quite complex and requires other components.
-- See DNS Shotgun
-- .RI ( https://gitlab.nic.cz/knot/shotgun )
-- for dnsjit scripts ready for use for high-performance
-- benchmarking.
module(...,package.seeall)

require("dnsjit.output.dnssim_h")
local bit = require("bit")
local object = require("dnsjit.core.objects")
local ffi = require("ffi")
local C = ffi.C

local DnsSim = {}

local _DNSSIM_VERSION = 20210129
local _DNSSIM_JSON_VERSION = 20200527

-- Create a new DnsSim output for up to max_clients.
function DnsSim.new(max_clients)
    local self = {
        obj = C.output_dnssim_new(max_clients),
        max_clients = max_clients,
    }
    ffi.gc(self.obj, C.output_dnssim_free)
    return setmetatable(self, { __index = DnsSim })
end

local function _check_version(version, req_version)
    if req_version == nil then
        return version
    end
    local min_version = tonumber(req_version)
    if min_version == nil then
        C.output_dnssim_log():fatal("invalid version number: "..req_version)
        return nil
    end
    if version >= min_version then
        return version
    end
    return nil
end

-- Check that version of dnssim is at minimum the one passed as
-- .B req_version
-- and return the actual version number.
-- Return nil if the condition is not met.
--
-- If no
-- .B req_version
-- is specified no check is done and only the version number is returned.
function DnsSim.check_version(req_version)
    return _check_version(_DNSSIM_VERSION, req_version)
end

-- Check that version of dnssim's JSON data format is at minimum the one passed as
-- .B req_version
-- and return the actual version number.
-- Return nil if the condition is not met.
--
-- If no
-- .B req_version
-- is specified no check is done and only the version number is returned.
function DnsSim.check_json_version(req_version)
    return _check_version(_DNSSIM_JSON_VERSION, req_version)
end

-- Return the Log object to control logging of this instance or module.
-- Optionally, set the instance's log name.
-- Unique name should be used for each instance.
function DnsSim:log(name)
    if self == nil then
        return C.output_dnssim_log()
    end
    if name ~= nil then
        C.output_dnssim_log_name(self.obj, name)
    end
    return self.obj._log
end

-- Set the target IPv4/IPv6 address where queries will be sent to.
function DnsSim:target(ip, port)
    local nport = tonumber(port)
    if nport == nil then
        self.obj._log:fatal("invalid port: "..port)
        return -1
    end
    if nport <= 0 or nport > 65535 then
        self.obj._log:fatal("invalid port number: "..nport)
        return -1
    end
    return C.output_dnssim_target(self.obj, ip, nport)
end

-- Specify source IPv4/IPv6 address for sending queries.
-- Can be set multiple times.
-- Addresses are selected round-robin when sending.
function DnsSim:bind(ip)
    return C.output_dnssim_bind(self.obj, ip)
end

-- Set the preferred transport to UDP.
--
-- When the optional argument
-- .B tcp_fallback
-- is set to true, individual queries are re-tried over TCP when TC bit is set in the answer.
-- Defaults to
-- .B false
-- (aka only UDP is used).
function DnsSim:udp(tcp_fallback)
    if tcp_fallback == true then
        C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_UDP)
    else
        C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY)
    end
end

-- Set the transport to TCP.
function DnsSim:tcp()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_TCP)
end

-- Set the transport to TLS.
--
-- The optional argument
-- .B tls_priority
-- is a GnuTLS priority string, which can be used to select TLS versions, cipher suites etc.
-- For example:
--
-- .RB "- """ NORMAL:%NO_TICKETS """"
-- will use defaults without TLS session resumption.
--
-- .RB "- """ SECURE128:-VERS-ALL:+VERS-TLS1.3 """"
-- will use only TLS 1.3 with 128-bit secure ciphers.
--
-- Refer to:
-- .I https://gnutls.org/manual/html_node/Priority-Strings.html
function DnsSim:tls(tls_priority)
    if tls_priority ~= nil then
        C.output_dnssim_tls_priority(self.obj, tls_priority)
    end
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_TLS)
end

-- Set the transport to HTTP/2 over TLS.
--
-- .B http2_options
-- is a lua table which supports the following keys:
--
-- .B method:
-- .B GET
-- (default)
-- or
-- .B POST
--
-- .B uri_path:
-- where queries will be sent.
-- Defaults to
-- .B /dns-query
--
-- .B zero_out_msgid:
-- when
-- .B true
-- (default), query ID is always set to 0
--
-- See tls() method for
-- .B tls_priority
-- documentation.
function DnsSim:https2(http2_options, tls_priority)
    if tls_priority ~= nil then
        C.output_dnssim_tls_priority(self.obj, tls_priority)
    end

    uri_path = "/dns-query"
    zero_out_msgid = true
    method = "GET"

    if http2_options ~= nil then
        if type(http2_options) ~= "table" then
            self.obj._log:fatal("http2_options must be a table")
        else
            if http2_options["uri_path"] ~= nil then
                uri_path = http2_options["uri_path"]
            end
            if http2_options["zero_out_msgid"] ~= nil and http2_options["zero_out_msgid"] ~= true then
                zero_out_msgid = false
            end
            if http2_options["method"] ~= nil then
                method = http2_options["method"]
            end
        end
    end

    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_HTTPS2)
    C.output_dnssim_h2_uri_path(self.obj, uri_path)
    C.output_dnssim_h2_method(self.obj, method)
    C.output_dnssim_h2_zero_out_msgid(self.obj, zero_out_msgid)
end

-- Set timeout for the individual requests in seconds (default 2s).
--
-- .BR Beware :
-- increasing this value while the target resolver isn't very responsive
-- (cold cache, heavy load) may degrade DnsSim's performance and skew
-- the results.
function DnsSim:timeout(seconds)
    if seconds == nil then
        seconds = 2
    end
    timeout_ms = math.floor(seconds * 1000)
    C.output_dnssim_timeout_ms(self.obj, timeout_ms)
end

-- Set TCP connection idle timeout for connection reuse according to RFC7766,
-- Section 6.2.3 (defaults to 10s).
-- When set to zero, connections are closed immediately after there are no
-- more pending queries.
function DnsSim:idle_timeout(seconds)
    if seconds == nil then
        seconds = 10
    end
    self.obj.idle_timeout_ms = math.floor(seconds * 1000)
end

-- Set TCP connection handshake timeout (defaults to 5s).
-- During heavy load, the server may no longer accept new connections.
-- This parameter ensures such connection attempts are aborted after the
-- timeout expires.
function DnsSim:handshake_timeout(seconds)
    if seconds == nil then
        seconds = 5
    end
    self.obj.handshake_timeout_ms = math.floor(seconds * 1000)
end

-- Run the libuv loop once without blocking when there is no I/O.
-- This should be called repeatedly until 0 is returned and no more data
-- is expected to be received by DnsSim.
function DnsSim:run_nowait()
    return C.output_dnssim_run_nowait(self.obj)
end

-- Set this to true if DnsSim should free the memory of passed-in objects
-- (useful when using
-- .I dnsjit.filter.copy
-- to pass objects from different thread).
function DnsSim:free_after_use(free_after_use)
    self.obj.free_after_use = free_after_use
end

-- Number of input packets discarded due to various reasons.
-- To investigate causes, run with increased logging level.
function DnsSim:discarded()
    return tonumber(self.obj.discarded)
end

-- Number of valid requests (input packets) processed.
function DnsSim:requests()
    return tonumber(self.obj.stats_sum.requests)
end

-- Number of requests that received an answer
function DnsSim:answers()
    return tonumber(self.obj.stats_sum.answers)
end

-- Number of requests that received a NOERROR response
function DnsSim:noerror()
    return tonumber(self.obj.stats_sum.rcode_noerror)
end

-- Configure statistics to be collected every N seconds.
function DnsSim:stats_collect(seconds)
    if seconds == nil then
        self.obj._log:fatal("number of seconds must be set for stats_collect()")
    end
    interval_ms = math.floor(seconds * 1000)
    C.output_dnssim_stats_collect(self.obj, interval_ms)
end

-- Stop the collection of statistics.
function DnsSim:stats_finish()
    C.output_dnssim_stats_finish(self.obj)
end

-- Export the results to a JSON file.
function DnsSim:export(filename)
    local file = io.open(filename, "w")
    if file == nil then
        self.obj._log:fatal("export failed: no filename")
        return
    end

    local function write_stats(file, stats)
        file:write(
            "{ ",
                '"since_ms":', tonumber(stats.since_ms), ',',
                '"until_ms":', tonumber(stats.until_ms), ',',
                '"requests":', tonumber(stats.requests), ',',
                '"ongoing":', tonumber(stats.ongoing), ',',
                '"answers":', tonumber(stats.answers), ',',
                '"conn_active":', tonumber(stats.conn_active), ',',
                '"conn_handshakes":', tonumber(stats.conn_handshakes), ',',
                '"conn_resumed":', tonumber(stats.conn_resumed), ',',
                '"conn_handshakes_failed":', tonumber(stats.conn_handshakes_failed), ',',
                '"rcode_noerror":', tonumber(stats.rcode_noerror), ',',
                '"rcode_formerr":', tonumber(stats.rcode_formerr), ',',
                '"rcode_servfail":', tonumber(stats.rcode_servfail), ',',
                '"rcode_nxdomain":', tonumber(stats.rcode_nxdomain), ',',
                '"rcode_notimp":', tonumber(stats.rcode_notimp), ',',
                '"rcode_refused":', tonumber(stats.rcode_refused), ',',
                '"rcode_yxdomain":', tonumber(stats.rcode_yxdomain), ',',
                '"rcode_yxrrset":', tonumber(stats.rcode_yxrrset), ',',
                '"rcode_nxrrset":', tonumber(stats.rcode_nxrrset), ',',
                '"rcode_notauth":', tonumber(stats.rcode_notauth), ',',
                '"rcode_notzone":', tonumber(stats.rcode_notzone), ',',
                '"rcode_badvers":', tonumber(stats.rcode_badvers), ',',
                '"rcode_badkey":', tonumber(stats.rcode_badkey), ',',
                '"rcode_badtime":', tonumber(stats.rcode_badtime), ',',
                '"rcode_badmode":', tonumber(stats.rcode_badmode), ',',
                '"rcode_badname":', tonumber(stats.rcode_badname), ',',
                '"rcode_badalg":', tonumber(stats.rcode_badalg), ',',
                '"rcode_badtrunc":', tonumber(stats.rcode_badtrunc), ',',
                '"rcode_badcookie":', tonumber(stats.rcode_badcookie), ',',
                '"rcode_other":', tonumber(stats.rcode_other), ',',
                '"latency":[')
        file:write(tonumber(stats.latency[0]))
        for i=1,tonumber(self.obj.timeout_ms) do
            file:write(',', tonumber(stats.latency[i]))
        end
        file:write("]}")
    end

    file:write(
        "{ ",
            '"version":', _DNSSIM_JSON_VERSION, ',',
            '"merged":false,',
            '"stats_interval_ms":', tonumber(self.obj.stats_interval_ms), ',',
            '"timeout_ms":', tonumber(self.obj.timeout_ms), ',',
            '"idle_timeout_ms":', tonumber(self.obj.idle_timeout_ms), ',',
            '"handshake_timeout_ms":', tonumber(self.obj.handshake_timeout_ms), ',',
            '"discarded":', self:discarded(), ',',
            '"stats_sum":')
    write_stats(file, self.obj.stats_sum)
    file:write(
            ',',
            '"stats_periodic":[')

    local stats = self.obj.stats_first
    write_stats(file, stats)

    while (stats.next ~= nil) do
        stats = stats.next
        file:write(',')
        write_stats(file, stats)
    end

    file:write(']}')
    file:close()
    self.obj._log:notice("results exported to "..filename)
end

-- Return the C function and context for receiving objects.
-- Only
-- .I dnsjit.filter.core.object.ip
-- or
-- .I dnsjit.filter.core.object.ip6
-- objects are supported.
-- The component expects a 32bit integer (in host order) ranging from 0
-- to max_clients written to first 4 bytes of destination IP.
-- See
-- .IR dnsjit.filter.ipsplit .
function DnsSim:receive()
    local receive = C.output_dnssim_receiver()
    return receive, self.obj
end

-- Deprecated: use udp() instead.
--
-- Set the transport to UDP (without any TCP fallback).
function DnsSim:udp_only()
    C.output_dnssim_set_transport(self.obj, C.OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY)
end

-- dnsjit.filter.copy (3),
-- dnsjit.filter.ipsplit (3),
-- dnsjit.filter.core.object.ip (3),
-- dnsjit.filter.core.object.ip6 (3),
-- https://gitlab.nic.cz/knot/shotgun
return DnsSim

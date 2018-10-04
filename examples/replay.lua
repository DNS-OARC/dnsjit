#!/usr/bin/env dnsjit
local clock = require("dnsjit.lib.clock")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
    { "R", "responses", false, "Wait for responses to the queries and print both", "?" },
    { "t", "tcp", false, "Use TCP instead of UDP", "?"},
})
local pcap, host, port = unpack(getopt:parse())
if getopt:val("help") then
    getopt:usage()
    return
end
local v = getopt:val("v")
if v > 0 then
    log.enable("warning")
end
if v > 1 then
    log.enable("notice")
end
if v > 2 then
    log.enable("info")
end
if v > 3 then
    log.enable("debug")
end

if pcap == nil or host == nil or port == nil then
    print("usage: "..arg[1].." <pcap> <host> <port>")
    return
end

local ffi = require("ffi")

local input = require("dnsjit.input.mmpcap").new()
local layer = require("dnsjit.filter.layer").new()
local output = require("dnsjit.output.udpcli").new()
if getopt:val("t") then
    output = require("dnsjit.output.tcpcli").new()
end
require("dnsjit.core.objects")
local dns = require("dnsjit.core.object.dns").new()

input:open(pcap)
layer:producer(input)
output:connect(host, port)

local printdns = false
if getopt:val("responses") then
    printdns = true
end

local prod, pctx = layer:produce()
local recv, rctx = output:receive()
local oprod, opctx = output:produce()
local start_sec, start_nsec = clock:monotonic()
if printdns then
    while true do
        local obj = prod(pctx)
        if obj == nil then break end
        local pl = obj:cast()
        if obj:type() == "payload" and pl.len > 0 then
            dns.obj_prev = obj
            if dns:parse_header() == 0 and dns.qr == 0 then
                print("query:")
                dns:print()

                recv(rctx, obj)

                local response = oprod(opctx)
                if response == nil then
                    log.fatal("producer error")
                end
                local payload = response:cast()
                if payload.len == 0 then
                    print("timed out")
                else
                    dns.obj_prev = response
                    print("response:")
                    dns:print()
                end
            end
        end
    end
else
    while true do
        local obj = prod(pctx)
        if obj == nil then break end
        local pl = obj:cast()
        if obj:type() == "payload" and pl.len > 0 then
            dns.obj_prev = obj
            if dns:parse_header() == 0 and dns.qr == 0 then
                recv(rctx, obj)
            end
        end
    end
end
local end_sec, end_nsec = clock:monotonic()

local runtime = 0
if end_sec > start_sec then
    runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
elseif end_sec == start_sec and end_nsec > start_nsec then
    runtime = (end_nsec - start_nsec) / 1000000000
end

print("runtime", runtime)
print("packets", input:packets(), input:packets()/runtime, "/pps")
print("queries", output:packets(), output:packets()/runtime, "/qps")
print("errors", output:errors())

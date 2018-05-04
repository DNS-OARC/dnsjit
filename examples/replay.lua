#!/usr/bin/env dnsjit
local clock = require("dnsjit.lib.clock")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
    { "R", "responses", false, "Wait for responses to the queries and print both", "?" },
    { "u", "udpcli", false, "Use output.udpcli for sending", "?"},
    { "t", "tcpcli", false, "Use output.tcpcli for sending", "?"},
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

if getopt:val("u") or getopt:val("t") then
    local input = require("dnsjit.input.mmpcap").new()
    input:open(pcap)
    local layer = require("dnsjit.filter.layer").new()
    layer:producer(input)

    local output
    if getopt:val("u") then
        output = require("dnsjit.output.udpcli").new()
    else
        output = require("dnsjit.output.tcpcli").new()
    end
    output:connect(host, port)

    local printdns = false
    if getopt:val("responses") then
        printdns = true
    end

    local prod, pctx = layer:produce()
    local recv, rctx = output:receive()
    local oprod, opctx = output:produce()

    local start_sec, start_nsec = clock:monotonic()
    while true do
        local obj = prod(pctx)
        if obj == nil then
            break
        end
        local dns = require("dnsjit.core.object.dns").new(obj)
        if dns and dns:parse() == 0 then
            if dns.qr == 0 then
                if printdns then
                    print("query:")
                    dns:print()
                    if recv(rctx, obj) == 0 then
                        local resp = nil
                        while resp == nil do
                            resp = oprod(opctx)
                        end
                        while resp ~= nil do
                            local dns = require("dnsjit.core.object.dns").new(resp)
                            if dns and dns:parse() == 0 then
                                print("response:")
                                dns:print()
                            end
                            resp = oprod(opctx)
                        end
                    end
                else
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
else
    local input = require("dnsjit.input.pcapthread").new()
    local output = require("dnsjit.output.cpool").new(host, port)

    input:only_queries(true)
    input:open_offline(pcap)

    if getopt:val("responses") then
        local lua = require("dnsjit.filter.lua").new()
        lua:func(function(f, obj)
            require("dnsjit.core.objects")
            local pkt = obj:cast()
            local dns = require("dnsjit.core.object.dns").new(obj)
            if pkt and dns and dns:parse() == 0 then
                print(pkt:src()..":"..pkt.sport.." -> "..pkt:dst()..":"..pkt.dport)
                dns:print()
            end
        end)
        output:receiver(lua)
    else
        output:skip_reply(true)
    end

    input:receiver(output)

    output:start()
    local start_sec, start_nsec = clock:monotonic()
    input:run()
    output:stop()
    local end_sec, end_nsec = clock:monotonic()

    local runtime = 0
    if end_sec > start_sec then
        runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
    elseif end_sec == start_sec and end_nsec > start_nsec then
        runtime = (end_nsec - start_nsec) / 1000000000
    end

    print("runtime", runtime)
    print("packets", input:packets(), input:packets()/runtime, "/pps")
    print("queries", input:queries(), input:queries()/runtime, "/qps")
    print("dropped", input:dropped())
    print("ignored", input:ignored())
    print("total", input:queries() + input:dropped() + input:ignored())
end

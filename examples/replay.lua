#!/usr/bin/env dnsjit
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
    { "R", "responses", false, "Wait for responses to the queries and print both", "?" },
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

local input = require("dnsjit.input.pcapthread").new()
local output = require("dnsjit.output.cpool").new(host, port)

input:only_queries(true)
input:open_offline(pcap)

if getopt:val("responses") then
    local lua = require("dnsjit.filter.lua").new()
    lua:func(function(f, pkt)
        local dns
        if pkt:type() == "packet" then
            dns = require("dnsjit.core.object.dns").new(pkt)
            if dns:parse() ~= 0 then
                return
            end
        elseif pkt:type() == "dns" then
            dns = pkt
            if dns:parse() ~= 0 then
                return
            end
            pkt = dns:prev()
            while pkt ~= nil do
                if pkt:type() == "packet" then
                    pkt = pkt:cast()
                    break
                end
                pkt = pkt:prev()
            end
            if pkt == nil then
                return
            end
        else
            return
        end

        if dns.qr == 0 then
            print(pkt:src()..":"..pkt.sport.." -> "..pkt:dst()..":"..pkt.dport)
        else
            print(pkt:dst()..":"..pkt.dport.." -> "..pkt:src()..":"..pkt.sport)
        end

        print("  id:", dns.id)
        local n = dns.questions
        while n > 0 and dns:rr_next() == 0 do
            if dns:rr_ok() == 1 then
                print("  qd:", dns:rr_class(), dns:rr_type(), dns:rr_label())
            end
            n = n - 1
        end
        n = dns.answers
        while n > 0 and dns:rr_next() == 0 do
            if dns:rr_ok() == 1 then
                print("  an:", dns:rr_class(), dns:rr_type(), dns:rr_ttl(), dns:rr_label())
            end
            n = n - 1
        end
        n = dns.authorities
        while n > 0 and dns:rr_next() == 0 do
            if dns:rr_ok() == 1 then
                print("  ns:", dns:rr_class(), dns:rr_type(), dns:rr_ttl(), dns:rr_label())
            end
            n = n - 1
        end
        n = dns.additionals
        while n > 0 and dns:rr_next() == 0 do
            if dns:rr_ok() == 1 then
                print("  ar:", dns:rr_class(), dns:rr_type(), dns:rr_ttl(), dns:rr_label())
            end
            n = n - 1
        end
    end)
    output:receiver(lua)
else
    output:skip_reply(true)
end

input:receiver(output)

output:start()
input:run()
output:stop()

local start_sec, start_nsec, end_sec, end_nsec, runtime

start_sec, start_nsec = input:start_time()
end_sec, end_nsec = input:end_time()
runtime = 0
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

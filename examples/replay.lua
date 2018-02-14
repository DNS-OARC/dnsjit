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

local input = require("dnsjit.input.pcap").new()
local output = require("dnsjit.output.cpool").new(host, port)

input:only_queries(true)
input:open_offline(pcap)

if getopt:val("responses") then
    local lua = require("dnsjit.filter.lua").new()
    lua:func(function(f, query)
        if not query:parse() then
            if query.qr == 0 then
                print(query:src()..":"..query.sport.." -> "..query:dst()..":"..query.dport)
            else
                print(query:dst()..":"..query.dport.." -> "..query:src()..":"..query.sport)
            end
            local n = query.questions
            while n > 0 and query:rr_next() == 0 do
                if query:rr_ok() == 1 then
                    print("  qd:", query:rr_class(), query:rr_type(), query:rr_label())
                end
                n = n - 1
            end
            n = query.answers
            while n > 0 and query:rr_next() == 0 do
                if query:rr_ok() == 1 then
                    print("  an:", query:rr_class(), query:rr_type(), query:rr_ttl(), query:rr_label())
                end
                n = n - 1
            end
            n = query.authorities
            while n > 0 and query:rr_next() == 0 do
                if query:rr_ok() == 1 then
                    print("  ns:", query:rr_class(), query:rr_type(), query:rr_ttl(), query:rr_label())
                end
                n = n - 1
            end
            n = query.additionals
            while n > 0 and query:rr_next() == 0 do
                if query:rr_ok() == 1 then
                    print("  ar:", query:rr_class(), query:rr_type(), query:rr_ttl(), query:rr_label())
                end
                n = n - 1
            end
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

#!/usr/bin/env dnsjit
local pcap = arg[2]
local host = arg[3]
local port = arg[4]

if pcap == nil or host == nil or port == nil then
    print("usage: "..arg[1].." <pcap> <host> <port>")
    return
end

local input = require("dnsjit.input.pcap").new()
local output = require("dnsjit.output.cpool").new(host, port)

input:only_queries(true)
input:open_offline(pcap)

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

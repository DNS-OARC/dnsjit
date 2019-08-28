#!/usr/bin/env dnsjit
local ffi = require("ffi")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
})
local pcap = unpack(getopt:parse())
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

if pcap == nil then
    print("usage: "..arg[1].." <pcap>")
    return
end


print("zero:receiver() -> dnssim:receive()")
local input = require("dnsjit.input.fpcap").new()
local layer = require("dnsjit.filter.layer").new()
local output = require("dnsjit.output.dnssim").new(65000)
input:open(pcap)
layer:producer(input)
output:udp_only()

local running = 0
local recv, rctx = output:receive()
local prod, pctx = layer:produce()

while true do
    pkt = prod(pctx)
    if pkt == nil then
        break
    end
    recv(rctx, pkt)
    running = output:run_nowait()
end

-- finish processing
while running ~= 0 do
    running = output:run_nowait()
end

print("dropped_pkts: "..tonumber(output.obj.dropped_pkts))
print("invalid_pkts: "..tonumber(output.obj.invalid_pkts))


print("zero:receiver() -> thread lua x1 -> dnssim:receive()")
local input = require("dnsjit.input.fpcap").new()
local layer = require("dnsjit.filter.layer").new()
local channel = require("dnsjit.core.channel").new()
local thread = require("dnsjit.core.thread").new()
input:open(pcap)
layer:producer(input)

thread:start(function(thread)
    local channel = thread:pop()
    local output = require("dnsjit.output.dnssim").new(65000)
    local running = 0
    output:udp_only()

    local recv, rctx = output:receive()
    while true do
        local obj = channel:get()
        if obj == nil then break end
        recv(rctx, obj)
        running = output:run_nowait()
    end

    while running ~= 0 do
        running = output:run_nowait()
    end

    print("dropped_pkts: "..tonumber(output.obj.dropped_pkts))
    print("invalid_pkts: "..tonumber(output.obj.invalid_pkts))
end)
thread:push(channel)

local prod, pctx = layer:produce()
while true do
    pkt = prod(pctx)
    if pkt == nil then
        break
    end
    channel:put(pkt)
end

channel:close()
thread:stop()

#!/usr/bin/env dnsjit
local ffi = require("ffi")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
})
getopt:parse()
local num = 10000
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


print("zero:receiver() -> dnssim:receive()")
local input = require("dnsjit.input.zero").new()
local output = require("dnsjit.output.dnssim").new()
output:udp_only()

local running = 0
local recv, rctx = output:receive()
local prod, pctx = input:produce()
for n = 1, num do
    recv(rctx, prod(pctx))
    running = output:run_nowait()
end

-- finish processing
while running ~= 0 do
    running = output:run_nowait()
end

print("dropped_pkts: "..output.obj.dropped_pkts)


print("zero:receiver() -> thread lua x1 -> dnssim:receive()")
local input = require("dnsjit.input.zero").new()
local channel = require("dnsjit.core.channel").new()
local thread = require("dnsjit.core.thread").new()

thread:start(function(thread)
    local channel = thread:pop()
    local output = require("dnsjit.output.dnssim").new()
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

    print("dropped_pkts: "..output.obj.dropped_pkts)
end)
thread:push(channel)

local prod, pctx = input:produce()
for n = 1, num do
    channel:put(prod(pctx))
end
channel:close()
thread:stop()

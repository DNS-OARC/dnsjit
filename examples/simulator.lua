#!/usr/bin/env dnsjit
local object = require("dnsjit.core.objects")
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

local input = require("dnsjit.input.fpcap").new()
local layer = require("dnsjit.filter.layer").new()
local channel = require("dnsjit.core.channel").new()
local thread = require("dnsjit.core.thread").new()
input:open(pcap)
layer:producer(input)

local function thread_main(thr)
    --local object = require("dnsjit.core.objects")
    local MAX_BATCH_SIZE = 32
    local chann = thr:pop()
    local output = require("dnsjit.output.dnssim").new(65000)
    local unique_id = tostring( {} ):sub(8)
    local running
    output:udp_only()
    output:target("::1", 53)
    output:free_after_use(true)

    local recv, rctx = output:receive()
    while true do
        local obj
        local i = 0

        -- read available data from channel
        while i < MAX_BATCH_SIZE do
            obj = chann:try_get()
            if obj == nil then break end
            recv(rctx, obj)
            i = i + 1
        end

        -- execute libuv loop
        running = output:run_nowait()

        -- check if channel is still open
        if obj == nil and chann.closed then
            break
        end
    end

    -- finish processing outstanding requests
    while running ~= 0 do
        running = output:run_nowait()
    end

    -- output results to file
    output:export("data_"..unique_id..".json")
end

-- initialize thread
thread:start(thread_main)
thread:push(channel)

-- read PCAP, parse, copy objects and pass to channel
local prod, pctx = layer:produce()
while true do
    local obj, payload, ip6
    local srcobj = prod(pctx)
    if srcobj == nil then break end

    -- find and copy payload object
    obj = srcobj:cast()
    while (obj.obj_type ~= object.PAYLOAD and obj.obj_prev ~= nil) do
        obj = obj.obj_prev:cast()
    end
    if obj.obj_type == object.PAYLOAD then
        payload = obj:copy()

        -- find and copy IP6 object
        while (obj.obj_type ~= object.IP6 and obj.obj_prev ~= nil) do
            obj = obj.obj_prev:cast()
        end
        if obj.obj_type == object.IP6 then
            ip6 = obj:copy()
            payload.obj_prev = ffi.cast("core_object_t*", ip6)

            channel:put(payload)
        end
    end
end

channel:close()
thread:stop()

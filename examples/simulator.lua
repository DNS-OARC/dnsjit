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
local output = require("dnsjit.output.dnssim").new(65000)
input:open(pcap)
layer:producer(input)
output:udp_only()
ret = output:target("::1", 53535)
if ret < 0 then
    return
end

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
print("clint0 req_total: "..tonumber(output.obj.client_arr[0].req_total))
print("clint26 req_total: "..tonumber(output.obj.client_arr[26].req_total))

--input:open(pcap)
--layer:producer(input)
--
--thread:start(function(thread)
--    local ffi  =require("ffi")
--    local object = require("dnsjit.core.objects")
--    local channel = thread:pop()
--    local output = require("dnsjit.output.dnssim").new(65000)
--    local running = 0
--    output:udp_only()
--
--    local recv, rctx = output:receive()
--    while true do
--        local obj = channel:get()
--        if obj == nil then break end
--        local pl = ffi.cast("core_object_t*", obj):cast()
--        while pl.obj_type ~= object.IP6 do
--            pl = pl.obj_prev:cast()
--        end
--        print(pl:source())
--        recv(rctx, obj)
--        running = output:run_nowait()
--    end
--
--    while running ~= 0 do
--        running = output:run_nowait()
--    end
--
--    print("dropped_pkts: "..tonumber(output.obj.dropped_pkts))
--end)
--thread:push(channel)
--
--local prod, pctx = layer:produce()
--while true do
--    local obj = prod(pctx)
--    if obj == nil then break end
--    local pl = obj:cast()
--    while pl.obj_type ~= object.IP6 do
--        pl = pl.obj_prev:cast()
--    end
--    print(pl:source())
--    --if obj:type() == "payload" and pl.len > 0 then
--    --    print("d")
--    --end
--
--    --if pkt:type() == "payload" then
--        --pkt.obj_prev
--
--    channel:put(obj)
--    --end
--end
--
--channel:close()
--thread:stop()

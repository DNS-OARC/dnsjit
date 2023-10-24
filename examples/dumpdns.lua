#!/usr/bin/env dnsjit
local pcap = arg[2]
local compression = arg[3]

if pcap == nil then
    print("usage: "..arg[1].." <pcap> [compression]")
    return
end

local object = require("dnsjit.core.objects")
local input = require("dnsjit.input.pcap").new()
local zinput = require("dnsjit.input.zpcap").new()
local layer = require("dnsjit.filter.layer").new()
local dns = require("dnsjit.core.object.dns").new()

if string.lower(string.sub(pcap, -4)) == ".zst" or compression == "zstd" then
    zinput:zstd()
    zinput:open(pcap)
    layer:producer(zinput)
elseif string.lower(string.sub(pcap, -4)) == ".lz4" or compression == "lz4" then
    zinput:lz4()
    zinput:open(pcap)
    layer:producer(zinput)
else
    input:open_offline(pcap)
    layer:producer(input)
end
local producer, ctx = layer:produce()

while true do
    local obj = producer(ctx)
    if obj == nil then break end
    local pl = obj:cast()
    if obj:type() == "payload" and pl.len > 0 then
        local transport = obj.obj_prev
        while transport ~= nil do
            if transport.obj_type == object.IP or transport.obj_type == object.IP6 then
                break
            end
            transport = transport.obj_prev
        end
        local protocol = obj.obj_prev
        while protocol ~= nil do
            if protocol.obj_type == object.UDP or protocol.obj_type == object.TCP then
                break
            end
            protocol = protocol.obj_prev
        end

        dns:reset()
        if protocol ~= nil and protocol.obj_type == object.TCP then
            dns.includes_dnslen = 1
        end
        dns.obj_prev = obj
        if transport ~= nil and protocol ~= nil then
            transport = transport:cast()
            protocol = protocol:cast()
            print(protocol:type().." "..transport:source()..":"..tonumber(protocol.sport).." -> "..transport:destination()..":"..tonumber(protocol.dport))
            dns:print()
        end
    end
end

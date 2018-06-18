#!/usr/bin/env dnsjit
local pcap = arg[2]

if pcap == nil then
    print("usage: "..arg[1].." <pcap>")
    return
end

local object = require("dnsjit.core.objects")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()

input:open_offline(pcap)
layer:producer(input)
local producer, ctx = layer:produce()

while true do
    local obj = producer(ctx)
    if obj == nil then break end
    if obj:type() == "payload" then
        local transport = obj.obj_prev
        while transport do
            if transport.obj_type == object.CORE_OBJECT_IP or transport.obj_type == object.CORE_OBJECT_IP6 then
                break
            end
            transport = transport.obj_prev
        end
        local protocol = obj.obj_prev
        while protocol do
            if protocol.obj_type == object.CORE_OBJECT_UDP or protocol.obj_type == object.CORE_OBJECT_TCP then
                break
            end
            protocol = protocol.obj_prev
        end

        local dns = require("dnsjit.core.object.dns").new(obj)
        if transport and protocol and dns and dns:parse() == 0 then
            transport = transport:cast()
            protocol = protocol:cast()
            print(protocol:type().." "..transport:source()..":"..tonumber(protocol.sport).." -> "..transport:destination()..":"..tonumber(protocol.dport))
            dns:print()
        end
    end
end

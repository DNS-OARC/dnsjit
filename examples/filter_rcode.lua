#!/usr/bin/env dnsjit
local pcap = arg[2]
local rcode = tonumber(arg[3])

if pcap == nil or rcode == nil then
    print("usage: "..arg[1].." <pcap> <rcode>")
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

        local dns = require("dnsjit.core.object.dns").new(obj)
        if transport and dns and dns:parse() == 0 and dns.have_rcode == 1 and dns.rcode == rcode then
            transport = transport:cast()
            print(dns.id, transport:source().." -> "..transport:destination())
        end
    end
end

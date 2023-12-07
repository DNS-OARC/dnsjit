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
local dns = require("dnsjit.core.object.dns").new()

input:open_offline(pcap)
layer:producer(input)
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
        if transport ~= nil and dns:parse_header() == 0 and dns.have_rcode == 1 and dns.rcode == rcode then
            transport = transport:cast()
            print(dns.id, transport:source().." -> "..transport:destination())
        end
    end
end

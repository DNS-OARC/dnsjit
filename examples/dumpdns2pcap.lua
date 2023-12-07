#!/usr/bin/env dnsjit
local pcap_in = arg[2]
local pcap_out = arg[3]

if pcap_in == nil or pcap_out == nil then
    print("usage: "..arg[1].." <pcap in> <pcap out>")
    return
end

local object = require("dnsjit.core.objects")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local dns = require("dnsjit.core.object.dns").new()
local output = require("dnsjit.output.pcap").new()

input:open_offline(pcap_in)
layer:producer(input)
local producer, ctx = layer:produce()

output:open(pcap_out, input:linktype(), input:snaplen())
local receiver, rctx = output:receive()

local n = 0
while true do
    local obj = producer(ctx)
    if obj == nil then break end
    local pl = obj:cast()
    if obj:type() == "payload" and pl.len > 0 then
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
        if dns:parse_header() == 0 then
            receiver(rctx, obj)
            n = n + 1
        end
    end
end

output:close()
print(n, "DNS packets dumped")

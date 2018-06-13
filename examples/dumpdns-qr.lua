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

local queries = {}
local responses = {}

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

            if dns.qr == 1 then
                table.insert(responses, {
                    src = transport:source(),
                    sport = protocol.sport,
                    dst = transport:destination(),
                    dport = protocol.dport,
                    id = dns.id,
                    rcode = dns.rcode,
                })
            else
                if dns.questions > 0 and dns:rr_next() == 0 and dns:rr_ok() then
                    table.insert(queries, {
                        src = transport:source(),
                        sport = protocol.sport,
                        dst = transport:destination(),
                        dport = protocol.dport,
                        id = dns.id,
                        qname = dns:rr_label(),
                        qtype = dns:rr_type(),
                    })
                end
            end
        end
    end
end

print("src", "dst", "id", "rcode", "qname", "qtype")
local q, r
for _, q in pairs(queries) do
    for _, r in pairs(responses) do
        if q.id == r.id and q.sport == r.dport and q.dport == r.sport and q.src == r.dst and q.dst == r.src then
            print(q.src, q.dst, q.id, r.rcode, q.qname, q.qtype)
        end
    end
end

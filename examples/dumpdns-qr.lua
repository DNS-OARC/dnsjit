#!/usr/bin/env dnsjit
local pcap = arg[2]

if pcap == nil then
    print("usage: "..arg[1].." <pcap>")
    return
end

local object = require("dnsjit.core.objects")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local dns = require("dnsjit.core.object.dns").new()
local label = require("dnsjit.core.object.dns.label")

local ffi = require("ffi")
local labels = require("dnsjit.core.object.dns.label").new(16)
local q = require("dnsjit.core.object.dns.q").new()

input:open_offline(pcap)
layer:producer(input)
local producer, ctx = layer:produce()

local queries = {}
local responses = {}

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

        dns.obj_prev = obj
        if transport ~= nil and protocol ~= nil and dns:parse_header() == 0 then
            transport = transport:cast()
            protocol = protocol:cast()

            if dns.qr == 1 then
                table.insert(responses, {
                    src = transport:source(),
                    sport = protocol.sport,
                    dst = transport:destination(),
                    dport = protocol.dport,
                    id = dns.id,
                    rcode = dns.rcode_tostring(dns.rcode),
                })
            else
                if dns.qdcount > 0 and dns:parse_q(q, labels, 16) == 0 then
                    table.insert(queries, {
                        src = transport:source(),
                        sport = protocol.sport,
                        dst = transport:destination(),
                        dport = protocol.dport,
                        id = dns.id,
                        qname = label.tooffstr(dns, labels, 16),
                        qtype = dns.type_tostring(q.type)
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

#!/usr/bin/env dnsjit
local ffi = require("ffi")
local getopt = require("dnsjit.lib.getopt").new({
})
local pcap, host, port = unpack(getopt:parse())

if pcap == nil or host == nil or port == nil then
    print("usage: "..arg[1].." <pcap> <host> <port>")
    return
end

local object = require("dnsjit.core.objects")

function tohex(p, l)
    local o, n = "", 0
    for n = 0, l do
        o = o .. string.format("%02x", p[n])
    end
    return o
end

local input = require("dnsjit.input.mmpcap").new()
input:open(pcap)
local layer = require("dnsjit.filter.layer").new()
layer:producer(input)

local udpcli, tcpcli
local udprecv, udpctx, tcprecv, tcpctx
local udpprod, tcpprod

local prod, pctx = layer:produce()
local queries = {}
local clipayload = ffi.new("core_object_payload_t")
clipayload.obj_type = object.CORE_OBJECT_PAYLOAD
local cliobject = ffi.cast("core_object_t*", clipayload)

print("id", "query", "original response")
print("", "", "received response")

while true do
    local obj = prod(pctx)
    if obj == nil then
        break
    end
    local dns = require("dnsjit.core.object.dns").new(obj)
    if dns and dns:parse() == 0 then
        local ip, proto, payload = obj, obj, obj:cast()
        while ip ~= nil and ip:type() ~= "ip" and ip:type() ~= "ip6" do
            ip = ip.obj_prev
        end
        while proto ~= nil and proto:type() ~= "udp" and proto:type() ~= "tcp" do
            proto = proto.obj_prev
        end
        if ip ~= nil and proto ~= nil then
            ip = ip:cast()
            proto = proto:cast()
            if dns.qr == 0 then
                local k = string.format("%s %d %s %d", ip:source(), proto.sport, ip:destination(), proto.dport)
                local q = {
                    id = dns.id,
                    proto = proto:type(),
                    payload = ffi.new("uint8_t[?]", payload.len),
                    len = tonumber(payload.len)
                }
                ffi.copy(q.payload, payload.payload, payload.len)
                queries[k] = q
            else
                local k = string.format("%s %d %s %d", ip:destination(), proto.dport, ip:source(), proto.sport)
                local q = queries[k]
                if q then
                    queries[k] = nil
                    clipayload.payload = q.payload
                    clipayload.len = q.len

                    local responses, response = {}, nil
                    if q.proto == "udp" then
                        if not udpcli then
                            udpcli = require("dnsjit.output.udpcli").new()
                            udpcli:connect(host, port)
                            udprecv, udpctx = udpcli:receive()
                            udpprod, _ = udpcli:produce()
                        end
                        udprecv(udpctx, cliobject)
                        while response == nil do
                            response = udpprod(udpctx)
                        end
                        while response ~= nil do
                            table.insert(responses, response)
                            response = udpprod(udpctx)
                        end
                    elseif q.proto == "tcp" then
                        if not tcpcli then
                            tcpcli = require("dnsjit.output.tcpcli").new()
                            tcpcli:connect(host, port)
                            tcprecv, tcpctx = tcpcli:receive()
                            tcpprod, _ = tcpcli:produce()
                        end
                        tcprecv(tcpctx, cliobject)
                        while response == nil do
                            response = tcpprod(tcpctx)
                        end
                        while response ~= nil do
                            table.insert(responses, response)
                            response = tcpprod(tcpctx)
                        end
                    end

                    print(dns.id, tohex(q.payload, q.len), tohex(payload.payload, tonumber(payload.len)))
                    for _, response in pairs(responses) do
                        local dns = require("dnsjit.core.object.dns").new(response)
                        if dns and dns:parse() == 0 and dns.id == q.id then
                            response = response:cast()
                            print("", "", tohex(response.payload, tonumber(response.len)))
                        end
                    end
                end
            end
        end
    end
end

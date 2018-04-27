#!/usr/bin/env dnsjit
local pcap = arg[2]

if pcap == nil then
    print("usage: "..arg[1].." <pcap>")
    return
end

require("dnsjit.core.object")
require("dnsjit.core.object.packet")

c = require("dnsjit.filter.coro").new()
queries = {}
responses = {}
c:func(function(c,o)
    local dns = require("dnsjit.core.object.dns").new(o)
    local pkt = o:cast()
    if dns and dns:parse() == 0 then
        if dns.qr == 1 then
            table.insert(responses, {
                src = pkt:src(),
                sport = pkt.sport,
                dst = pkt:dst(),
                dport = pkt.dport,
                id = dns.id,
                rcode = dns.rcode,
            })
        else
            if dns.questions > 0 and dns:rr_next() == 0 and dns:rr_ok() then
                table.insert(queries, {
                    src = pkt:src(),
                    sport = pkt.sport,
                    dst = pkt:dst(),
                    dport = pkt.dport,
                    id = dns.id,
                    qname = dns:rr_label(),
                    qtype = dns:rr_type(),
                })
            end
        end
    end
end)

i = require("dnsjit.input.pcapthread").new()
i:receiver(c)
i:open_offline(pcap)
i:run()

print("src", "dst", "id", "rcode", "qname", "qtype")
for _, q in pairs(queries) do
    for _, r in pairs(responses) do
        if q.id == r.id and q.sport == r.dport and q.dport == r.sport and q.src == r.dst and q.dst == r.src then
            print(q.src, q.dst, q.id, r.rcode, q.qname, q.qtype)
        end
    end
end

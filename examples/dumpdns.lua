#!/usr/bin/env dnsjit
local pcap = arg[2]

if pcap == nil then
    print("usage: "..arg[1].." <pcap>")
    return
end

local input = require("dnsjit.input.pcapthread").new()
local output = require("dnsjit.filter.lua").new()

output:func(function(filter, pkt)
    require("dnsjit.core.object.packet")
    local dns
    if pkt:type() == "packet" then
        dns = require("dnsjit.core.object.dns").new(pkt)
        if dns:parse() ~= 0 then
            return
        end
    elseif pkt:type() == "dns" then
        dns = pkt
        if dns:parse() ~= 0 then
            return
        end
        pkt = dns:prev()
        while pkt ~= nil do
            if pkt:type() == "packet" then
                pkt = pkt:cast()
                break
            end
            pkt = pkt:prev()
        end
        if pkt == nil then
            return
        end
    else
        return
    end

    print(pkt:src()..":"..pkt.sport.." -> "..pkt:dst()..":"..pkt.dport)

    print("  id:", dns.id)
    local n = dns.questions
    while n > 0 and dns:rr_next() == 0 do
        if dns:rr_ok() == 1 then
            print("  qd:", dns:rr_class(), dns:rr_type(), dns:rr_label())
        end
        n = n - 1
    end
    n = dns.answers
    while n > 0 and dns:rr_next() == 0 do
        if dns:rr_ok() == 1 then
            print("  an:", dns:rr_class(), dns:rr_type(), dns:rr_ttl(), dns:rr_label())
        end
        n = n - 1
    end
    n = dns.authorities
    while n > 0 and dns:rr_next() == 0 do
        if dns:rr_ok() == 1 then
            print("  ns:", dns:rr_class(), dns:rr_type(), dns:rr_ttl(), dns:rr_label())
        end
        n = n - 1
    end
    n = dns.additionals
    while n > 0 and dns:rr_next() == 0 do
        if dns:rr_ok() == 1 then
            print("  ar:", dns:rr_class(), dns:rr_type(), dns:rr_ttl(), dns:rr_label())
        end
        n = n - 1
    end
end)

input:open_offline(pcap)
input:receiver(output)
input:run()

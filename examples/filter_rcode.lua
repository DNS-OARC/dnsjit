#!/usr/bin/env dnsjit
local pcap = arg[2]
local rcode = arg[3]

if pcap == nil or rcode == nil then
    print("usage: "..arg[1].." <pcap> <rcode>")
    return
end

local input = require("dnsjit.input.pcapthread").new()
local output = require("dnsjit.filter.lua").new()

output:push(tonumber(rcode))
output:func(function(filter, obj, args)
    require("dnsjit.core.object.packet")
    local pkt = obj:cast()
    local rcode = unpack(args, 0)
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

    if dns.have_rcode == 1 and dns.rcode == rcode then
        print(dns.id, pkt:src().." -> "..pkt:dst())
    end
end)

input:open_offline(pcap)
input:receiver(output)
input:run()

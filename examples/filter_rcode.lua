#!/usr/bin/env dnsjit
local pcap = arg[2]
local rcode = tonumber(arg[3])

if pcap == nil or rcode == nil then
    print("usage: "..arg[1].." <pcap> <rcode>")
    return
end

require("dnsjit.core.objects")

local input = require("dnsjit.input.pcapthread").new()
local output = require("dnsjit.filter.coro").new()

output:func(function(filter, obj)
    local pkt = obj:cast()
    local dns = require("dnsjit.core.object.dns").new(obj)
    if pkt and dns and dns:parse() == 0 and dns.have_rcode == 1 and dns.rcode == rcode then
        print(dns.id, pkt:src().." -> "..pkt:dst())
    end
end)

input:open_offline(pcap)
input:receiver(output)
input:run()

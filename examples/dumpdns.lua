#!/usr/bin/env dnsjit
local pcap = arg[2]

if pcap == nil then
    print("usage: "..arg[1].." <pcap>")
    return
end

require("dnsjit.core.objects")

local input = require("dnsjit.input.pcapthread").new()
local output = require("dnsjit.filter.coro").new()

output:func(function(filter, obj)
    local pkt = obj:cast()
    local dns = require("dnsjit.core.object.dns").new(obj)
    if pkt and dns and dns:parse() == 0 then
        print(pkt:src()..":"..pkt.sport.." -> "..pkt:dst()..":"..pkt.dport)
        dns:print()
    end
end)

input:open_offline(pcap)
input:receiver(output)
input:run()

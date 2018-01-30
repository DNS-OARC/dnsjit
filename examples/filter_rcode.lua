#!/usr/bin/env dnsjit
local pcap = arg[2]
local rcode = arg[3]

if pcap == nil or rcode == nil then
    print("usage: "..arg[1].." <pcap> <rcode>")
    return
end

local input = require("dnsjit.input.pcap").new()
local output = require("dnsjit.filter.lua").new()

output:push(tonumber(rcode))
output:func(function(filter, query, args)
    local rcode = unpack(args, 0)
    query:parse()
    if query:rcode() == rcode then
        print(query:id(), query:src().." -> "..query:dst())
    end
end)

input:open_offline(pcap)
input:receiver(output)
input:run()

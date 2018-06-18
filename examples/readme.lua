#!/usr/bin/env dnsjit
require("dnsjit.core.objects")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()

input:open_offline(arg[2])
layer:producer(input)
local producer, ctx = layer:produce()

while true do
    local object = producer(ctx)
    if object == nil then break end
    if object:type() == "payload" then
        local dns = require("dnsjit.core.object.dns").new(object)
        if dns and dns:parse() == 0 then
            print(dns.id)
        end
    end
end

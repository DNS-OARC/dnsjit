#!/usr/bin/env dnsjit

-- Disclaimer, to keep this example short it only works on pre-prepared
-- PCAPs with only UDP DNS traffic in them.

require("dnsjit.core.objects")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local dns = require("dnsjit.core.object.dns").new()

input:open_offline(arg[2])
layer:producer(input)
local producer, ctx = layer:produce()

while true do
    local object = producer(ctx)
    if object == nil then break end
    if object:type() == "payload" then
        dns:reset()
        dns.obj_prev = object
        if dns:parse_header() == 0 then
            print(dns.id)
        end
    end
end

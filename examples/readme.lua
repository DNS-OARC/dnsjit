#!/usr/bin/env dnsjit
local input = require("dnsjit.input.pcapthread").new()
local output = require("dnsjit.filter.lua").new()

output:func(function(filter, object)
    local packet = object:cast()
    local dns = require("dnsjit.core.object.dns").new(packet)
    if dns:parse() == 0 then
        print(dns.id)
    end
end)

input:open_offline(arg[2])
input:only_queries(true)
input:receiver(output)
input:run()

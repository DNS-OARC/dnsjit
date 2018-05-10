#!/usr/bin/env dnsjit
require("dnsjit.core.objects")
local input = require("dnsjit.input.pcapthread").new()
local output = require("dnsjit.filter.coro").new()

output:func(function(filter, object)
    local dns = require("dnsjit.core.object.dns").new(object)
    if dns and dns:parse() == 0 then
        print(dns.id)
    end
end)

input:open_offline(arg[2])
input:only_queries(true)
input:receiver(output)
input:run()

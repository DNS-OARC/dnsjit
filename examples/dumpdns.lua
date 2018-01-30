#!/usr/bin/env dnsjit
local pcap = arg[2]

if pcap == nil then
    print("usage: "..arg[1].." <pcap>")
    return
end

local input = require("dnsjit.input.pcap").new()
local output = require("dnsjit.filter.lua").new()

output:func(function(filter, query)
    print(query:src()..":"..query:sport().." -> "..query:dst()..":"..query:dport())
    if not query:parse() then
        local n = query:questions()
        while n > 0 and query:rr_next() == 0 do
            if query:rr_ok() == 1 then
                print("  qd:", query:rr_class(), query:rr_type(), query:rr_label())
            end
            n = n - 1
        end
        n = query:answers()
        while n > 0 and query:rr_next() == 0 do
            if query:rr_ok() == 1 then
                print("  an:", query:rr_class(), query:rr_type(), query:rr_ttl(), query:rr_label())
            end
            n = n - 1
        end
        n = query:authorities()
        while n > 0 and query:rr_next() == 0 do
            if query:rr_ok() == 1 then
                print("  ns:", query:rr_class(), query:rr_type(), query:rr_ttl(), query:rr_label())
            end
            n = n - 1
        end
        n = query:additionals()
        while n > 0 and query:rr_next() == 0 do
            if query:rr_ok() == 1 then
                print("  ar:", query:rr_class(), query:rr_type(), query:rr_ttl(), query:rr_label())
            end
            n = n - 1
        end
    end
end)

input:open_offline(pcap)
input:receiver(output)
input:run()

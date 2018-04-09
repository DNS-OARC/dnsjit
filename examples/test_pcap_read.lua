#!/usr/bin/env dnsjit
local clock = require("dnsjit.lib.clock")
local pcap = arg[2]
local runs = tonumber(arg[3])

if pcap == nil then
    print("usage: "..arg[1].." <pcap> [runs]")
    return
end

inputs = { "fpcap", "mmpcap", "pcap", "pcapthread" }
result = {}
results = {}
highest = nil

if runs == nil then
    runs = 10
else
    runs = tonumber(runs)
end

for _, name in pairs(inputs) do
    rt = 0.0
    p = 0

    print("run", name)
    for n = 1, runs do
        o = require("dnsjit.output.null").new()
        i = require("dnsjit.input."..name).new()
        if name == "pcap" then
            i:open_offline(pcap)
            i:receiver(o)
            ss, sns = clock:monotonic()
            i:dispatch()
        elseif name == "pcapthread" then
            i:open_offline(pcap)
            i:receiver(o)
            ss, sns = clock:monotonic()
            i:run()
        else
            i:open(pcap)
            i:receiver(o)
            ss, sns = clock:monotonic()
            i:run()
        end
        es, ens = clock:monotonic()

        if es > ss then
            rt = rt + ((es - ss) - 1) + ((1000000000 - sns + ens)/1000000000)
        elseif es == ss and ens > sns then
            rt = rt + (ens - sns) / 1000000000
        end

        p = p + o:packets()
    end

    result[name] = {
        rt = rt,
        p = p
    }
    if highest == nil or rt > result[highest].rt then
        highest = name
    end
    table.insert(results, name)
end

print("name", "runtime", "pps", "x", "pkts")
print(highest, result[highest].rt, result[highest].p/result[highest].rt, 1.0, result[highest].p)
for _, name in pairs(results) do
    if name ~= highest then
        print(name, result[name].rt, result[name].p/result[name].rt, result[highest].rt/result[name].rt, result[name].p)
    end
end

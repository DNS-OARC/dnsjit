#!/usr/bin/env dnsjit
local clock = require("dnsjit.lib.clock")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
    { "l", "layer", false, "Test also with dnsjit.filter.layer", "?" },
    { "p", "producer", false, "Test with the producer interface rather then receiver interface", "?" },
})
local pcap, runs = unpack(getopt:parse())
if getopt:val("help") then
    getopt:usage()
    return
end
local v = getopt:val("v")
if v > 0 then
    log.enable("warning")
end
if v > 1 then
    log.enable("notice")
end
if v > 2 then
    log.enable("info")
end
if v > 3 then
    log.enable("debug")
end

if pcap == nil then
    print("usage: "..arg[1].." <pcap> [runs]")
    return
end

inputs = { "fpcap", "mmpcap", "pcap" }
result = {}
results = {}
highest = nil

if runs == nil then
    runs = 10
else
    runs = tonumber(runs)
end

if getopt:val("p") then
    for _, name in pairs(inputs) do
        rt = 0.0
        p = 0

        print("run", name)
        for n = 1, runs do
            o = require("dnsjit.output.null").new()
            i = require("dnsjit.input."..name).new()

            if name == "pcap" then
                i:open_offline(pcap)
            else
                i:open(pcap)
            end

            if getopt:val("l") then
                f = require("dnsjit.filter.layer").new()
                f:producer(i)
                o:producer(f)
            else
                o:producer(i)
            end

            ss, sns = clock:monotonic()
            o:run()
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
else
    for _, name in pairs(inputs) do
        rt = 0.0
        p = 0

        print("run", name)
        for n = 1, runs do
            o = require("dnsjit.output.null").new()
            i = require("dnsjit.input."..name).new()

            if name == "pcap" then
                i:open_offline(pcap)
            else
                i:open(pcap)
            end

            if getopt:val("l") then
                f = require("dnsjit.filter.layer").new()
                f:receiver(o)
                i:receiver(f)
            else
                i:receiver(o)
            end

            ss, sns = clock:monotonic()
            if name == "pcap" then
                i:dispatch()
            else
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
end

print("name", "runtime", "pps", "x", "pkts")
print(highest, result[highest].rt, result[highest].p/result[highest].rt, 1.0, result[highest].p)
for _, name in pairs(results) do
    if name ~= highest then
        local f = result[name].p / result[highest].p
        print(name, result[name].rt, result[name].p/result[name].rt, (result[highest].rt/result[name].rt)*f, result[name].p)
    end
end

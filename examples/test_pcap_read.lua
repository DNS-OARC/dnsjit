#!/usr/bin/env dnsjit
local clock = require("dnsjit.lib.clock")
local getopt = require("dnsjit.lib.getopt").new({
    { "t", "thread", 0, "Test also with dnsjit.filter.thread, give number of threads to run", "?" },
    { "l", "layer", false, "Test also with dnsjit.filter.layer", "?" },
    { "p", "producer", false, "Test with the producer interface rather then receiver interface", "?" },
})
local pcap, runs = unpack(getopt:parse())
if getopt:val("help") then
    getopt:usage()
    return
end

if pcap == nil then
    print("usage: "..arg[1].." <pcap> [runs]")
    return
end

if getopt:val("p") then
    inputs = { "fpcap", "mmpcap", "pcap" }
else
    inputs = { "fpcap", "mmpcap", "pcap", "pcapthread" }
end
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
            t = nil
            tos = nil
            -- if getopt:val("t") > 1 then
            --     local nn
            --     tos = {}
            --     o = require("dnsjit.filter.thread").new()
            --     for nn = 1, getopt:val("t") do
            --         local oo = require("dnsjit.output.null").new()
            --         o:receiver(oo)
            --         table.insert(tos, oo)
            --     end
            --     o:start()
            --     t = o
            -- else
                o = require("dnsjit.output.null").new()
            -- end
            i = require("dnsjit.input."..name).new()
            if name == "pcap" then
                i:open_offline(pcap)
                if getopt:val("l") then
                    f = require("dnsjit.filter.layer").new()
                    f:producer(i)
                    o:producer(f)
                else
                    o:producer(i)
                end
                ss, sns = clock:monotonic()
                -- i:dispatch()
                o:run(0)
            else
                -- if t then
                    -- i:use_shared(true)
                -- end
                i:open(pcap)
                if getopt:val("l") then
                    f = require("dnsjit.filter.layer").new()
                    f:producer(i)
                    o:producer(f)
                else
                    o:producer(i)
                end
                ss, sns = clock:monotonic()
                -- i:run()
                o:run(0)
            end
            if t then
                t:stop()
            end
            es, ens = clock:monotonic()

            if es > ss then
                rt = rt + ((es - ss) - 1) + ((1000000000 - sns + ens)/1000000000)
            elseif es == ss and ens > sns then
                rt = rt + (ens - sns) / 1000000000
            end

            if tos then
                for _, oo in pairs(tos) do
                    p = p + oo:packets()
                end
            else
                p = p + o:packets()
            end
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
            t = nil
            tos = nil
            if getopt:val("t") > 1 then
                local nn
                tos = {}
                o = require("dnsjit.filter.thread").new()
                for nn = 1, getopt:val("t") do
                    local oo = require("dnsjit.output.null").new()
                    o:receiver(oo)
                    table.insert(tos, oo)
                end
                o:start()
                t = o
            else
                o = require("dnsjit.output.null").new()
            end
            i = require("dnsjit.input."..name).new()
            if name == "pcap" then
                i:open_offline(pcap)
                if getopt:val("l") then
                    f = require("dnsjit.filter.layer").new()
                    f:receiver(o)
                    i:receiver(f)
                else
                    i:receiver(o)
                end
                ss, sns = clock:monotonic()
                i:dispatch()
            elseif name == "pcapthread" then
                i:open_offline(pcap)
                i:receiver(o)
                ss, sns = clock:monotonic()
                i:run()
            else
                if t then
                    i:use_shared(true)
                end
                i:open(pcap)
                if getopt:val("l") then
                    f = require("dnsjit.filter.layer").new()
                    f:receiver(o)
                    i:receiver(f)
                else
                    i:receiver(o)
                end
                ss, sns = clock:monotonic()
                i:run()
            end
            if t then
                t:stop()
            end
            es, ens = clock:monotonic()

            if es > ss then
                rt = rt + ((es - ss) - 1) + ((1000000000 - sns + ens)/1000000000)
            elseif es == ss and ens > sns then
                rt = rt + (ens - sns) / 1000000000
            end

            if name == "pcapthread" then
                p = p + i:packets()
            else
                if tos then
                    for _, oo in pairs(tos) do
                        p = p + oo:packets()
                    end
                else
                    p = p + o:packets()
                end
            end
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

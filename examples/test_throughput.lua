#!/usr/bin/env dnsjit
local num = tonumber(arg[2])
local runs = tonumber(arg[3])

if num == nil then
    print("usage: "..arg[1].." <num> [runs]")
    return
end

if runs == nil or not type(runs) == "number" or runs < 1 then
    runs = 1
end

local input = require("dnsjit.input.zero").new()
local output = require("dnsjit.output.null").new()

input:receiver(output)

local run
for run = 1, runs do
    input:run(num)

    local start_sec, start_nsec = input:start_time()
    local end_sec, end_nsec = input:end_time()
    local runtime = 0
    if end_sec > start_sec then
        runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
    elseif end_sec == start_sec and end_nsec > start_nsec then
        runtime = (end_nsec - start_nsec) / 1000000000
    end

    print("run", run)
    print("runtime", runtime)
    print("num", num)
    print("throughput", num/runtime, "/sec")
end

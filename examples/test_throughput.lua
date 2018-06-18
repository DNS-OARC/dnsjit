#!/usr/bin/env dnsjit
local ffi = require("ffi")
local object = require("dnsjit.core.objects")
local clock = require("dnsjit.lib.clock")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
    { "s", "split", false, "Test also with dnsjit.filter.split", "?" }
})
local num, runs = unpack(getopt:parse())
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

if num == nil then
    print("usage: "..arg[1].." <num> [runs]")
    return
else
    num = tonumber(num)
end

if runs == nil then
    runs = 1
else
    runs = tonumber(runs)
end

print("zero:receiver() -> null:receive()")
local run
for run = 1, runs do
    local i = require("dnsjit.input.zero").new()
    local o = require("dnsjit.output.null").new()

    i:receiver(o)
    local start_sec, start_nsec = clock:monotonic()
    i:run(num)
    local end_sec, end_nsec = clock:monotonic()

    local runtime = 0
    if end_sec > start_sec then
        runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
    elseif end_sec == start_sec and end_nsec > start_nsec then
        runtime = (end_nsec - start_nsec) / 1000000000
    end

    print(run, "runtime", runtime, num/runtime, "/sec", o:packets())
end

print("lua -> null:receive()")
local run
for run = 1, runs do
    local o = require("dnsjit.output.null").new()
    local recv, rctx = o:receive()
    local pkt = ffi.new("core_object_null_t")
    pkt.obj_type = object.CORE_OBJECT_NULL
    local obj = ffi.cast("core_object_t*", pkt)

    local start_sec, start_nsec = clock:monotonic()
    for n = 1, num do
        recv(rctx, obj)
    end
    local end_sec, end_nsec = clock:monotonic()

    local runtime = 0
    if end_sec > start_sec then
        runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
    elseif end_sec == start_sec and end_nsec > start_nsec then
        runtime = (end_nsec - start_nsec) / 1000000000
    end

    print(run, "runtime", runtime, num/runtime, "/sec", o:packets())
end

-- TODO: use core.thread

print("zero:produce() <- null:producer()")
local run
for run = 1, runs do
    local i = require("dnsjit.input.zero").new()
    local o = require("dnsjit.output.null").new()

    local start_sec, start_nsec = clock:monotonic()
    o:producer(i)
    o:run(num)
    local end_sec, end_nsec = clock:monotonic()

    local runtime = 0
    if end_sec > start_sec then
        runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
    elseif end_sec == start_sec and end_nsec > start_nsec then
        runtime = (end_nsec - start_nsec) / 1000000000
    end

    print(run, "runtime", runtime, num/runtime, "/sec", o:packets())
end

print("zero:produce() <- lua")
local run
for run = 1, runs do
    local i = require("dnsjit.input.zero").new()
    local prod, pctx = i:produce()

    local start_sec, start_nsec = clock:monotonic()
    for n = 1, num do
        prod(pctx)
    end
    local end_sec, end_nsec = clock:monotonic()

    local runtime = 0
    if end_sec > start_sec then
        runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
    elseif end_sec == start_sec and end_nsec > start_nsec then
        runtime = (end_nsec - start_nsec) / 1000000000
    end

    print(run, "runtime", runtime, num/runtime, "/sec", num)
end

print("zero:produce() <- lua -> null:receive()")
local run
for run = 1, runs do
    local i = require("dnsjit.input.zero").new()
    local o = require("dnsjit.output.null").new()
    local prod, pctx = i:produce()
    local recv, rctx = o:receive()

    local start_sec, start_nsec = clock:monotonic()
    for n = 1, num do
        recv(rctx, prod(pctx))
    end
    local end_sec, end_nsec = clock:monotonic()

    local runtime = 0
    if end_sec > start_sec then
        runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
    elseif end_sec == start_sec and end_nsec > start_nsec then
        runtime = (end_nsec - start_nsec) / 1000000000
    end

    print(run, "runtime", runtime, num/runtime, "/sec", num)
end

if getopt:val("s") then
    print("zero:receiver() -> split:receiver() -> null:receive() x1")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local s = require("dnsjit.filter.split").new()
        local o1 = require("dnsjit.output.null").new()

        s:receiver(o1)
        i:receiver(s)
        local start_sec, start_nsec = clock:monotonic()
        i:run(num)
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec", o1:packets(), o1:packets())
    end

    print("zero:receiver() -> split:receiver() -> null:receive() x2")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local s = require("dnsjit.filter.split").new()
        local o1 = require("dnsjit.output.null").new()
        local o2 = require("dnsjit.output.null").new()

        s:receiver(o1)
        s:receiver(o2)
        i:receiver(s)
        local start_sec, start_nsec = clock:monotonic()
        i:run(num)
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec", o1:packets() + o2:packets(), o1:packets(), o2:packets())
    end

    print("zero:receiver() -> split:receiver() -> null:receive() x4")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local s = require("dnsjit.filter.split").new()
        local o1 = require("dnsjit.output.null").new()
        local o2 = require("dnsjit.output.null").new()
        local o3 = require("dnsjit.output.null").new()
        local o4 = require("dnsjit.output.null").new()

        s:receiver(o1)
        s:receiver(o2)
        s:receiver(o3)
        s:receiver(o4)
        i:receiver(s)
        local start_sec, start_nsec = clock:monotonic()
        i:run(num)
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec", o1:packets() + o2:packets() + o3:packets() + o4:packets(), o1:packets(), o2:packets(), o3:packets(), o4:packets())
    end
end

#!/usr/bin/env dnsjit
local clock = require("dnsjit.lib.clock")
local getopt = require("dnsjit.lib.getopt").new({
    { "t", "thread", false, "Test also with dnsjit.filter.thread", "?" },
    { "c", "coro", false, "Test also with dnsjit.filter.coro", "?" },
    { "s", "split", false, "Test also with dnsjit.filter.split", "?" }
})
local num, runs = unpack(getopt:parse())
if getopt:val("help") then
    getopt:usage()
    return
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

if getopt:val("t") then
    print("zero:receiver() -> thread:receiver() -> null:receive()")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local t = require("dnsjit.filter.thread").new()
        local o = require("dnsjit.output.null").new()

        t:receiver(o)
        i:receiver(t)
        t:start()
        i:use_shared(true)
        local start_sec, start_nsec = clock:monotonic()
        i:run(num)
        t:stop()
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec", o:packets())
    end

    print("zero:receiver() -> thread:receiver() -> null:receive() x2")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local t = require("dnsjit.filter.thread").new()
        local o1 = require("dnsjit.output.null").new()
        local o2 = require("dnsjit.output.null").new()

        t:receiver(o1)
        t:receiver(o2)
        i:receiver(t)
        t:start()
        i:use_shared(true)
        local start_sec, start_nsec = clock:monotonic()
        i:run(num)
        t:stop()
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec", o1:packets() + o2:packets(), o1:packets(), o2:packets())
    end

    print("zero:receiver() -> thread:receiver() -> null:receive() x4")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local t = require("dnsjit.filter.thread").new()
        local o1 = require("dnsjit.output.null").new()
        local o2 = require("dnsjit.output.null").new()
        local o3 = require("dnsjit.output.null").new()
        local o4 = require("dnsjit.output.null").new()

        t:receiver(o1)
        t:receiver(o2)
        t:receiver(o3)
        t:receiver(o4)
        i:receiver(t)
        t:start()
        i:use_shared(true)
        local start_sec, start_nsec = clock:monotonic()
        i:run(num)
        t:stop()
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

if getopt:val("s") then
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
end

if getopt:val("s") and getopt:val("t") then
    print("zero:receiver() -> split:receiver() -> thread:receiver() x2 -> null:receive() x2")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local s = require("dnsjit.filter.split").new()
        local t1 = require("dnsjit.filter.thread").new()
        local o1 = require("dnsjit.output.null").new()
        local t2 = require("dnsjit.filter.thread").new()
        local o2 = require("dnsjit.output.null").new()

        t1:receiver(o1)
        t1:start()
        t2:receiver(o2)
        t2:start()

        s:receiver(t1)
        s:receiver(t2)
        i:receiver(s)
        i:use_shared(true)
        local start_sec, start_nsec = clock:monotonic()
        i:run(num)
        t1:stop()
        t2:stop()
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec", o1:packets() + o2:packets(), o1:packets(), o2:packets())
    end
end

if getopt:val("c") then
    print("zero:receiver() -> coro:receiver() -> null:receive()")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local c = require("dnsjit.filter.coro").new()
        local o = require("dnsjit.output.null").new()

        c:receiver(o)
        c:func(function(c,obj)
            c:send(obj)
        end)
        i:receiver(c)
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
end

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

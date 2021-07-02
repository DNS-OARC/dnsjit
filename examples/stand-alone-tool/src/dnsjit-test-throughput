#!/usr/bin/env dnsjit
local ffi = require("ffi")
local object = require("dnsjit.core.objects")
local clock = require("dnsjit.lib.clock")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
    { "s", "split", false, "Test also with dnsjit.filter.split", "?" },
    { "t", "thread", false, "Test also with dnsjit.core.thread using dnsjit.core.channel", "?" },
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
    pkt.obj_type = object.NULL
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

    print("zero:receiver() -> lua split table -> null:receive() x4")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local o1 = require("dnsjit.output.null").new()
        local o2 = require("dnsjit.output.null").new()
        local o3 = require("dnsjit.output.null").new()
        local o4 = require("dnsjit.output.null").new()

        local prod, pctx = i:produce()
        local recv, rctx = {}, {}

        local f, c = o1:receive()
        table.insert(recv, f)
        table.insert(rctx, c)
        f, c = o2:receive()
        table.insert(recv, f)
        table.insert(rctx, c)
        f, c = o3:receive()
        table.insert(recv, f)
        table.insert(rctx, c)
        f, c = o4:receive()
        table.insert(recv, f)
        table.insert(rctx, c)

        local start_sec, start_nsec = clock:monotonic()
        local idx = 1
        for n = 1, num do
            local f, c = recv[idx], rctx[idx]
            if not f then
                idx = 1
                f, c = recv[1], rctx[1]
            end
            f(c, prod(pctx))
            idx = idx + 1
        end
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec", o1:packets() + o2:packets() + o3:packets() + o4:packets(), o1:packets(), o2:packets(), o3:packets(), o4:packets())
    end

    print("zero:receiver() -> lua split gen code -> null:receive() x4")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local o1 = require("dnsjit.output.null").new()
        local o2 = require("dnsjit.output.null").new()
        local o3 = require("dnsjit.output.null").new()
        local o4 = require("dnsjit.output.null").new()

        local prod, pctx = i:produce()
        local f1, c1 = o1:receive()
        local f2, c2 = o2:receive()
        local f3, c3 = o3:receive()
        local f4, c4 = o4:receive()

        local code = "return function (num, prod, pctx, f1, c1, f2, c2, f3, c3, f4, c4)\nlocal n = 0\nwhile n < num do\n"
        code = code .. "f1(c1,prod(pctx))\n"
        code = code .. "n = n + 1\n"
        code = code .. "f2(c2,prod(pctx))\n"
        code = code .. "n = n + 1\n"
        code = code .. "f3(c3,prod(pctx))\n"
        code = code .. "n = n + 1\n"
        code = code .. "f4(c4,prod(pctx))\n"
        code = code .. "n = n + 1\n"
        code = code .. "end\n"
        code = code .. "end"
        local f = assert(loadstring(code))()

        local start_sec, start_nsec = clock:monotonic()
        f(num, prod, pctx, f1, c1, f2, c2, f3, c3, f4, c4)
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

if getopt:val("t") then
    print("zero:receiver() -> thread lua x1")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local c = require("dnsjit.core.channel").new()
        local t = require("dnsjit.core.thread").new()

        t:start(function(t)
            local c = t:pop()

            while true do
                local o = c:get()
                if o == nil then break end
            end
        end)
        t:push(c)

        local prod, pctx = i:produce()
        local start_sec, start_nsec = clock:monotonic()
        for n = 1, num do
            c:put(prod(pctx))
        end
        c:close()
        t:stop()
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec")
    end

    print("zero:receiver() -> thread lua x2")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local c = require("dnsjit.core.channel").new()
        local c2 = require("dnsjit.core.channel").new()
        local t = require("dnsjit.core.thread").new()
        local t2 = require("dnsjit.core.thread").new()

        local f = function(t)
            local c = t:pop()

            while true do
                local o = c:get()
                if o == nil then break end
            end
        end

        t:start(f)
        t2:start(f)
        t:push(c)
        t2:push(c2)

        local prod, pctx = i:produce()
        local start_sec, start_nsec = clock:monotonic()
        for n = 1, num/2 do
            c:put(prod(pctx))
            c2:put(prod(pctx))
        end
        c:close()
        c2:close()
        t:stop()
        t2:stop()
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec")
    end

    print("zero:receiver() -> thread lua x4")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local c = require("dnsjit.core.channel").new()
        local c2 = require("dnsjit.core.channel").new()
        local c3 = require("dnsjit.core.channel").new()
        local c4 = require("dnsjit.core.channel").new()
        local t = require("dnsjit.core.thread").new()
        local t2 = require("dnsjit.core.thread").new()
        local t3 = require("dnsjit.core.thread").new()
        local t4 = require("dnsjit.core.thread").new()

        local f = function(t)
            local c = t:pop()

            while true do
                local o = c:get()
                if o == nil then break end
            end
        end

        t:start(f)
        t2:start(f)
        t3:start(f)
        t4:start(f)
        t:push(c)
        t2:push(c2)
        t3:push(c3)
        t4:push(c4)

        local prod, pctx = i:produce()
        local start_sec, start_nsec = clock:monotonic()
        for n = 1, num/4 do
            c:put(prod(pctx))
            c2:put(prod(pctx))
            c3:put(prod(pctx))
            c4:put(prod(pctx))
        end
        c:close()
        c2:close()
        c3:close()
        c4:close()
        t:stop()
        t2:stop()
        t3:stop()
        t4:stop()
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec")
    end

    print("zero:receiver() -> thread lua x1 -> null:receiver()")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local c = require("dnsjit.core.channel").new()
        local t = require("dnsjit.core.thread").new()

        t:start(function(t)
            local c = t:pop()
            local o = require("dnsjit.output.null").new()

            local recv, rctx = o:receive()
            while true do
                local obj = c:get()
                if obj == nil then break end
                recv(rctx, obj)
            end
        end)
        t:push(c)

        local prod, pctx = i:produce()
        local start_sec, start_nsec = clock:monotonic()
        for n = 1, num do
            c:put(prod(pctx))
        end
        c:close()
        t:stop()
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec")
    end

    print("zero:receiver() -> thread x1 -> null:receiver()")
    local run
    for run = 1, runs do
        local i = require("dnsjit.input.zero").new()
        local c = require("dnsjit.core.channel").new()
        local t = require("dnsjit.core.thread").new()

        t:start(function(t)
            local c = t:pop()
            local o = require("dnsjit.output.null").new()

            c:receiver(o)
            c:run()
        end)
        t:push(c)

        i:receiver(c)
        local start_sec, start_nsec = clock:monotonic()
        i:run(num)
        c:close()
        t:stop()
        local end_sec, end_nsec = clock:monotonic()

        local runtime = 0
        if end_sec > start_sec then
            runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
        elseif end_sec == start_sec and end_nsec > start_nsec then
            runtime = (end_nsec - start_nsec) / 1000000000
        end

        print(run, "runtime", runtime, num/runtime, "/sec")
    end
end

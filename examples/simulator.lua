#!/usr/bin/env dnsjit
local ffi = require("ffi")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
})
local num = 100000
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


print("zero:receiver() -> dnssim:receive()")
local i = require("dnsjit.input.zero").new()
local o = require("dnsjit.output.dnssim").new()

i:receiver(o)
i:run(num)


print("zero:receiver() -> thread lua x1 -> dnssim:receive()")
local i = require("dnsjit.input.zero").new()
local c = require("dnsjit.core.channel").new()
local t = require("dnsjit.core.thread").new()

t:start(function(t)
    local c = t:pop()
    local o = require("dnsjit.output.dnssim").new()

    local recv, rctx = o:receive()
    while true do
        local obj = c:get()
        if obj == nil then break end
        recv(rctx, obj)
    end
end)
t:push(c)

local prod, pctx = i:produce()
for n = 1, num do
    c:put(prod(pctx))
end
c:close()
t:stop()

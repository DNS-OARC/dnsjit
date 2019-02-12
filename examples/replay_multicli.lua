#!/usr/bin/env dnsjit
local clock = require("dnsjit.lib.clock")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "c", "clients", 10, "Number of clients run", "?" },
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
    { "R", "responses", false, "Wait for responses to the queries and print both", "?" },
    { "t", "tcp", false, "Use TCP instead of UDP", "?"},
    { "T", "tls", false, "Use TLS instead of UDP/TCP", "?"},
})
local pcap, host, port = unpack(getopt:parse())
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

if pcap == nil or host == nil or port == nil then
    print("usage: "..arg[1].." <pcap> <host> <port>")
    return
end

local ffi = require("ffi")

require("dnsjit.core.objects")
local input = require("dnsjit.input.mmpcap").new()
local layer = require("dnsjit.filter.layer").new()

input:open(pcap)
layer:producer(input)

local query = require("dnsjit.core.object.dns").new()
local response = require("dnsjit.core.object.dns").new()

local dnscli = require("dnsjit.output.dnscli")

local clients = {}
local last_client = nil
local num_clients = getopt:val("c")
for n = 1, num_clients do
    local output
    if getopt:val("t") then
        output = dnscli.new(dnscli.TCP + dnscli.NONBLOCKING)
    elseif getopt:val("T") then
        output = dnscli.new(dnscli.TLS + dnscli.NONBLOCKING)
    else
        output = dnscli.new(dnscli.UDP + dnscli.NONBLOCKING)
    end
    output:connect(host, port)

    local recv, rctx = output:receive()
    local prod, pctx = output:produce()
    local client = {
        output = output,
        last = last_client,
        busy = false,
        recv = recv, rctx = rctx,
        prod = prod, pctx = pctx,
        id = nil,
        done = false,
    }
    table.insert(clients, client)
    last_client = client
end
local output = clients[1]
output.last = last_client

if getopt:val("t") then
    response.includes_dnslen = 1
elseif getopt:val("T") then
    response.includes_dnslen = 1
end

local printdns = false
if getopt:val("responses") then
    printdns = true
end

local prod, pctx = layer:produce()
local start_sec, start_nsec = clock:monotonic()

local done = false
while true do
    output = output.last
    if printdns and output.busy then
        local pobj = output.prod(output.pctx)
        if pobj == nil then
            log.fatal("producer error")
        end
        local rpl = pobj:cast()
        if rpl.len == 0 then
            -- print(output, "busy")
        else
            response.obj_prev = pobj
            if response:parse_header() == 0 and response.qr == 1 and response.id == output.id then
                print("response:")
                response:print()
                output.busy = false
            end
        end
    end
    if not output.busy then
        while true do
            local obj = prod(pctx)
            if obj == nil then
                done = true
                break
            end
            local pl = obj:cast()
            if obj:type() == "payload" and pl.len > 0 then
                query.obj_prev = obj

                local trs = pl.obj_prev:cast()
                if trs:type() == "tcp" then
                    query.includes_dnslen = 1
                else
                    query.includes_dnslen = 0
                end

                if query:parse_header() == 0 and query.qr == 0 then
                    output.recv(output.rctx, query:uncast())
                    if printdns then
                        print("query:")
                        query:print()
                        output.busy = true
                        output.id = query.id
                    end
                    break
                end
            end
        end
    end
    if done then break end
end

local queries, timeouts, errors = 0, 0, 0
done = 0
while true do
    output = output.last
    if printdns and output.busy then
        local pobj = output.prod(output.pctx)
        if pobj == nil then
            log.fatal("producer error")
        end
        local rpl = pobj:cast()
        if rpl.len == 0 then
            -- print(output, "busy")
        else
            response.obj_prev = pobj
            if response:parse_header() == 0 and response.qr == 1 and response.id == output.id then
                print("response:")
                response:print()
                output.busy = false
            end
        end
    end
    if not output.busy and not output.done then
        output.done = true
        done = done + 1
        queries = queries + output.output:packets()
        timeouts = timeouts + output.output:timeouts()
        errors = errors + output.output:errors()
    end
    if done >= num_clients then break end
end

local end_sec, end_nsec = clock:monotonic()

local runtime = 0
if end_sec > start_sec then
    runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
elseif end_sec == start_sec and end_nsec > start_nsec then
    runtime = (end_nsec - start_nsec) / 1000000000
end

print("runtime", runtime)
print("packets", input:packets(), input:packets()/runtime, "/pps")
print("queries", queries, queries/runtime, "/qps")
print("timeouts", timeouts)
print("errors", errors)

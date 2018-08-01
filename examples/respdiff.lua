#!/usr/bin/env dnsjit
local ffi = require("ffi")
local clock = require("dnsjit.lib.clock")
local log = require("dnsjit.core.log")
log.display_file_line(true)
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
})
local pcap, host, port, path, origname, recvname = unpack(getopt:parse())
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

if pcap == nil or host == nil or port == nil or path == nil or origname == nil or recvname == nil then
    print("usage: "..arg[1].." <pcap> <host> <port> <LMDB path> <origname> <recvname>")
    return
end

local object = require("dnsjit.core.objects")
local dns = require("dnsjit.core.object.dns").new()
local input = require("dnsjit.input.mmpcap").new()
input:open(pcap)
local layer = require("dnsjit.filter.layer").new()
layer:producer(input)

local udpcli, tcpcli
local udprecv, udpctx, tcprecv, tcpctx
local udpprod, tcpprod

local prod, pctx = layer:produce()
local queries = {}
local clipayload = ffi.new("core_object_payload_t")
clipayload.obj_type = object.PAYLOAD
local cliobject = ffi.cast("core_object_t*", clipayload)

local respdiff = require("dnsjit.output.respdiff").new(path, origname, recvname)
local resprecv, respctx = respdiff:receive()
local query_payload, original_payload, response_payload = ffi.new("core_object_payload_t"), ffi.new("core_object_payload_t"), ffi.new("core_object_payload_t")
query_payload.obj_type = object.PAYLOAD
original_payload.obj_type = object.PAYLOAD
response_payload.obj_type = object.PAYLOAD
local query_payload_obj = ffi.cast("core_object_t*", query_payload)
query_payload.obj_prev = ffi.cast("core_object_t*", original_payload)
original_payload.obj_prev = ffi.cast("core_object_t*", response_payload)

local start_sec, start_nsec = clock:realtime()
while true do
    local obj = prod(pctx)
    if obj == nil then break end
    local payload = obj:cast()
    if obj:type() == "payload" and payload.len > 0 then
        dns.obj_prev = obj
        if dns:parse_header() == 0 then
            local transport = obj.obj_prev
            while transport ~= nil do
                if transport.obj_type == object.IP or transport.obj_type == object.IP6 then
                    break
                end
                transport = transport.obj_prev
            end
            local protocol = obj.obj_prev
            while protocol ~= nil do
                if protocol.obj_type == object.UDP or protocol.obj_type == object.TCP then
                    break
                end
                protocol = protocol.obj_prev
            end

            if transport ~= nil and protocol ~= nil then
                transport = transport:cast()
                protocol = protocol:cast()

                if dns.qr == 0 then
                    local k = string.format("%s %d %s %d", transport:source(), protocol.sport, transport:destination(), protocol.dport)
                    local q = {
                        id = dns.id,
                        proto = protocol:type(),
                        payload = ffi.new("uint8_t[?]", payload.len),
                        len = tonumber(payload.len)
                    }
                    ffi.copy(q.payload, payload.payload, payload.len)
                    queries[k] = q
                else
                    local k = string.format("%s %d %s %d", transport:destination(), protocol.dport, transport:source(), protocol.sport)
                    local q = queries[k]
                    if q then
                        queries[k] = nil
                        clipayload.payload = q.payload
                        clipayload.len = q.len

                        local prod, pctx

                        if q.proto == "udp" then
                            if not udpcli then
                                udpcli = require("dnsjit.output.udpcli").new()
                                udpcli:connect(host, port)
                                udprecv, udpctx = udpcli:receive()
                                udpprod, _ = udpcli:produce()
                            end
                            udprecv(udpctx, cliobject)
                            prod = udpprod
                            pctx = udpctx
                        elseif q.proto == "tcp" then
                            if not tcpcli then
                                tcpcli = require("dnsjit.output.tcpcli").new()
                                tcpcli:connect(host, port)
                                tcprecv, tcpctx = tcpcli:receive()
                                tcpprod, _ = tcpcli:produce()
                            end
                            tcprecv(tcpctx, cliobject)
                            prod = tcpprod
                            pctx = tcpctx
                        end

                        while true do
                            local response = prod(pctx)
                            if response == nil then
                                log.fatal("producer error")
                            end
                            local rpl = response:cast()
                            if rpl.len == 0 then
                                log.info("timed out")
                            else
                                dns.obj_prev = response
                                if dns:parse_header() == 0 and dns.id == q.id then
                                    query_payload.payload = q.payload
                                    query_payload.len = q.len
                                    original_payload.payload = payload.payload
                                    original_payload.len = payload.len
                                    response_payload.payload = rpl.payload
                                    response_payload.len = rpl.len

                                    resprecv(respctx, query_payload_obj)
                                    break
                                end
                            end
                        end
                    end
                end
            end
        end
    end
end
local end_sec, end_nsec = clock:realtime()

respdiff:commit(start_sec, end_sec)

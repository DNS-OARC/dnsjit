#!/usr/bin/env dnsjit
local clock = require("dnsjit.lib.clock")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
    { "r", "read-state", "", "File to read state from before processing", "?" },
    { "w", "write-state", "", "File to write state to after processing", "?" },
})
local pcap = unpack(getopt:parse())
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
    print("usage: "..arg[1].." <pcap>")
    return
end

local object = require("dnsjit.core.objects")
local input = require("dnsjit.input.mmpcap").new()
local layer = require("dnsjit.filter.layer").new()
local dns = require("dnsjit.core.object.dns").new()
local label = require("dnsjit.core.object.dns.label")
local ffi = require("ffi")
local labels = require("dnsjit.core.object.dns.label").new(16)
local q = require("dnsjit.core.object.dns.q").new()
local bit = require("bit")

hash_u32 = ffi.new("uint32_t[2]")
hash_u32p = ffi.cast("uint32_t*", hash_u32)
function hashkey(dns, transport, protocol)
    if transport.obj_type == object.IP then
        ffi.copy(hash_u32p, transport.src, 4)
        hash_u32[1] = hash_u32[0]
        ffi.copy(hash_u32p, transport.dst, 4)
        hash_u32[1] = bit.bxor(hash_u32[0], hash_u32[1])
    else
        local srcp = ffi.cast("uint8_t*", transport.src)
        ffi.copy(hash_u32p, srcp, 4)
        hash_u32[1] = hash_u32[0]
        ffi.copy(hash_u32p, srcp+4, 4)
        hash_u32[1] = bit.bxor(hash_u32[0], hash_u32[1])
        srcp = ffi.cast("uint8_t*", transport.dst)
        ffi.copy(hash_u32p, srcp, 4)
        hash_u32[1] = bit.bxor(hash_u32[0], hash_u32[1])
        ffi.copy(hash_u32p, srcp+4, 4)
        hash_u32[1] = bit.bxor(hash_u32[0], hash_u32[1])
    end
    if dns.qr == 1 then
        hash_u32[0] = protocol.dport + bit.lshift(protocol.sport, 16)
    else
        hash_u32[0] = protocol.sport + bit.lshift(protocol.dport, 16)
    end
    hash_u32[1] = bit.bxor(hash_u32[0], hash_u32[1])
    hash_u32[0] = dns.id + bit.lshift(dns.id, 16)
    return bit.bxor(hash_u32[0], hash_u32[1])
end

function dump_inflight(hkey, obj)
    return string.format("return %d, { qsec = %d, qnsec = %d, rsec = %d, rnsec = %d, src = %q, sport = %d, dst = %q, dport = %d, id = %d, qname = %q, qtype = %q, rcode = %d }",
        hkey,
        tonumber(obj.qsec), tonumber(obj.qnsec),
        tonumber(obj.rsec), tonumber(obj.rnsec),
        obj.src, obj.sport,
        obj.dst, obj.dport,
        obj.id,
        obj.qname, obj.qtype,
        obj.rcode
    )
end

function qrout(res)
    local tsq = tonumber(res.qsec) + (tonumber(res.qnsec)/1000000000)
    local tsr = tonumber(res.rsec) + (tonumber(res.rnsec)/1000000000)
    print(tsq, tsr, math.floor(((tsr-tsq)*1000000)+0.5),
        res.src, res.dst, res.id, res.rcode, res.qname, res.qtype)
end

input:open(pcap)
layer:producer(input)
local producer, ctx = layer:produce()

local inflight = {}

if getopt:val("read-state") > "" then
    local f, _ = io.open(getopt:val("read-state"))
    local inflights = 0
    if f ~= nil then
        for chunk in f:lines() do
            local hkey, query = assert(loadstring(chunk))()
            if hkey and query then
                if not inflight[hkey] then
                    inflight[hkey] = {
                        queries = {},
                        size = 0,
                    }
                end

                table.insert(inflight[hkey].queries, query)
                inflight[hkey].size = inflight[hkey].size + 1
                inflights = inflights + 1
            end
        end
        f:close()
        print(string.format("== read %d inflight states from %q", inflights, getopt:val("read-state")))
    end
end

local stat = {
    packets = 0,
    queries = 0,
    responses = 0,
    dropped = 0,
}
local start_sec, start_nsec = clock:monotonic()
while true do
    local obj = producer(ctx)
    if obj == nil then break end
    stat.packets = stat.packets + 1
    local pl = obj:cast()
    if obj:type() == "payload" and pl.len > 0 then
        local protocol = obj.obj_prev
        while protocol ~= nil do
            if protocol.obj_type == object.UDP or protocol.obj_type == object.TCP then
                break
            end
            protocol = protocol.obj_prev
        end
        local transport = protocol.obj_prev
        while transport ~= nil do
            if transport.obj_type == object.IP or transport.obj_type == object.IP6 then
                break
            end
            transport = transport.obj_prev
        end
        local pcap = transport.obj_prev
        while pcap ~= nil do
            if pcap.obj_type == object.PCAP then
                break
            end
            pcap = pcap.obj_prev
        end

        dns.obj_prev = obj
        if pcap ~= nil and transport ~= nil and protocol ~= nil and dns:parse_header() == 0 then
            transport = transport:cast()
            protocol = protocol:cast()
            pcap = pcap:cast()

            local hkey = hashkey(dns, transport, protocol)

            if dns.qr == 1 then
                stat.responses = stat.responses + 1
                if inflight[hkey] then
                    for k, n in pairs(inflight[hkey].queries) do
                        if n.id == dns.id
                            and n.sport == protocol.dport
                            and n.dport == protocol.sport
                            and n.src == transport:destination()
                            and n.dst == transport:source()
                        then
                            n.rsec = pcap.ts.sec
                            n.rnsec = pcap.ts.nsec
                            n.rcode = dns.rcode
                            qrout(n)
                            inflight[hkey].queries[k] = nil
                            inflight[hkey].size = inflight[hkey].size - 1
                            if inflight[hkey].size < 1 then
                                inflight[hkey] = nil
                            end
                            break
                        end
                    end
                else
                    print("== dropped",
                        tonumber(pcap.ts.sec) + (tonumber(pcap.ts.nsec) / 1000000000),
                        transport:source(),
                        transport:destination(),
                        dns.id,
                        label.tooffstr(dns, labels, 16),
                        dns.type_tostring(q.type)
                    )
                    stat.dropped = stat.dropped + 1
                end
            else
                stat.queries = stat.queries + 1
                if dns.qdcount > 0 and dns:parse_q(q, labels, 16) == 0 then
                    if not inflight[hkey] then
                        inflight[hkey] = {
                            queries = {},
                            size = 0,
                        }
                    end

                    table.insert(inflight[hkey].queries, {
                        qsec = pcap.ts.sec,
                        qnsec = pcap.ts.nsec,
                        rsec = -1,
                        rnsec = -1,
                        src = transport:source(),
                        sport = protocol.sport,
                        dst = transport:destination(),
                        dport = protocol.dport,
                        id = dns.id,
                        qname = label.tooffstr(dns, labels, 16),
                        qtype = dns.type_tostring(q.type),
                        rcode = -1,
                    })
                    inflight[hkey].size = inflight[hkey].size + 1
                end
            end
        end
    end
end
local end_sec, end_nsec = clock:monotonic()

local runtime = 0
if end_sec > start_sec then
    runtime = ((end_sec - start_sec) - 1) + ((1000000000 - start_nsec + end_nsec)/1000000000)
elseif end_sec == start_sec and end_nsec > start_nsec then
    runtime = (end_nsec - start_nsec) / 1000000000
end

print("== runtime", runtime)
print("== packets", stat.packets, stat.packets/runtime)
print("== queries", stat.queries, stat.queries/runtime)
print("== responses", stat.responses, stat.responses/runtime)
print("== dropped", stat.dropped, stat.dropped/runtime)

if getopt:val("write-state") > "" then
    local f, _ = io.open(getopt:val("write-state"), "w+")
    local inflights = 0
    if f ~= nil then
        for hkey, unanswered in pairs(inflight) do
            for _, query in pairs(unanswered.queries) do
                f:write(dump_inflight(hkey, query), "\n")
                inflights = inflights + 1
            end
        end
        f:close()
        print(string.format("== wrote %d inflight states to %q", inflights, getopt:val("write-state")))
    end
else
    inflights = 0
    for hkey, unanswered in pairs(inflight) do
        inflights = inflights + unanswered.size
    end
    if inflights > 0 then
        print("== inflight queries (tsq, src, dst, id, qname, qtype)")
        for hkey, unanswered in pairs(inflight) do
            for _, query in pairs(unanswered.queries) do
                print(tonumber(query.qsec) + (tonumber(query.qnsec)/1000000000), query.src, query.dst, query.id, query.qname, query.qtype)
            end
        end
    end
end

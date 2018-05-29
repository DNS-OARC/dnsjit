#!/usr/bin/env dnsjit
local ffi = require("ffi")
local clock = require("dnsjit.lib.clock")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
    { "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
    { "m", "match", false, "Group query with response from the PCAP and match it against the received response", "?" },
    { nil, "respdiff", "", "Use output.respdiff to write out query, original and received response to the specified LMDB path", "?" },
    { nil, "respdiff-origname", "", "The name of the server in respdiff.cfg for the original responses", "?" },
    { nil, "respdiff-recvname", "", "The name of the server in respdiff.cfg for the received responses", "?" },
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

local object = require("dnsjit.core.objects")

local matchcfg = {
    opcode = 1,
    qtype = 1,
    qname = 1,
    qcase = 1,
    flags = 1,
    rcode = 1,
    question = 1,
    answer = 1,
    ttl = 1,
    answertypes = 1,
    answerrrsigs = 1,
    authority = 1,
    additional = 1,
    edns = 1,
    nsid = 1,
}

function tohex(p, l)
    local o, n = "", 0
    for n = 0, l do
        o = o .. string.format("%02x", p[n])
    end
    return o
end

function extract(dns)
    local data = {
        flags = {},
        flags_str = "",
        questions = {},
        answers = {},
        authorities = {},
        additionals = {}
    }

    if dns.have_aa and dns.aa == 1 then
        table.insert(data.flags, "AA")
    end
    if dns.have_tc and dns.tc == 1 then
        table.insert(data.flags, "TC")
    end
    if dns.have_rd and dns.rd == 1 then
        table.insert(data.flags, "RD")
    end
    if dns.have_ra and dns.ra == 1 then
        table.insert(data.flags, "RA")
    end
    if dns.have_z and dns.z == 1 then
        table.insert(data.flags, "Z")
    end
    if dns.have_ad and dns.ad == 1 then
        table.insert(data.flags, "AD")
    end
    if dns.have_cd and dns.cd == 1 then
        table.insert(data.flags, "CD")
    end
    data.flags_str = table.concat(data.flags, " ")

    local n = dns.questions
    while n > 0 and dns:rr_next() == 0 do
        if dns:rr_ok() == 1 then
            table.insert(data.questions, {
                class = dns:rr_class(),
                type = dns:rr_type(),
                label = dns:rr_label()
            })
        end
        n = n - 1
    end
    n = dns.answers
    while n > 0 and dns:rr_next() == 0 do
        if dns:rr_ok() == 1 then
            table.insert(data.answers, {
                class = dns:rr_class(),
                type = dns:rr_type(),
                ttl = dns:rr_ttl(),
                label = dns:rr_label()
            })
        end
        n = n - 1
    end
    n = dns.authorities
    while n > 0 and dns:rr_next() == 0 do
        if dns:rr_ok() == 1 then
            table.insert(data.authorities, {
                class = dns:rr_class(),
                type = dns:rr_type(),
                ttl = dns:rr_ttl(),
                label = dns:rr_label()
            })
        end
        n = n - 1
    end
    n = dns.additionals
    while n > 0 and dns:rr_next() == 0 do
        if dns:rr_ok() == 1 then
            table.insert(data.additionals, {
                class = dns:rr_class(),
                type = dns:rr_type(),
                ttl = dns:rr_ttl(),
                label = dns:rr_label()
            })
        end
        n = n - 1
    end

    return data
end

function compare_val(name, exp, got)
    if exp == nil or got == nil or exp ~= got then
        return name.." missmatch, exp != got: " .. string.format("%s != %s", exp, got)
    end
end

function compare_rrs_label(name, exp, got)
    local e, g
    if exp == nil then
        return { name.." missmatch, exp != got: exp is nil" }
    end
    if got == nil then
        return { name.." missmatch, exp != got: got is nil" }
    end
    local results = {}
    for _, e in pairs(exp) do
        local found = false
        for _, g in pairs(got) do
            if g.label == e.label then
                found = true
                break
            end
        end
        if not found then
            results[e.label] = name.." missmatch, exp != got: missing label " .. e.label
        end
    end
    for _, g in pairs(got) do
        local found = false
        for _, e in pairs(exp) do
            if e.label == g.label then
                found = true
                break
            end
        end
        if not found then
            results[g.label] = name.." missmatch, exp != got: got extra label " .. g.label
        end
    end
    return results
end

function compare_rrs_type(name, exp, got)
    local e, g
    if exp == nil then
        return { name.." missmatch, exp != got: exp is nil" }
    end
    if got == nil then
        return { name.." missmatch, exp != got: got is nil" }
    end
    local results = {}
    for _, e in pairs(exp) do
        local found = false
        for _, g in pairs(got) do
            if g.type == e.type then
                found = true
                break
            end
        end
        if not found then
            results[e.type] = name.." missmatch, exp != got: missing type " .. e.type
        end
    end
    for _, g in pairs(got) do
        local found = false
        for _, e in pairs(exp) do
            if e.type == g.type then
                found = true
                break
            end
        end
        if not found then
            results[g.type] = name.." missmatch, exp != got: got extra type " .. g.type
        end
    end
    return results
end

function match(orig, resp)
    local results = {}
    local orig_data = extract(orig)
    local resp_data = extract(resp)

    if matchcfg.opcode == 1 then
        local result = compare_val("opcode", orig.opcode, resp.opcode)
        if result then
            table.insert(results, result)
        end
    end
    if matchcfg.qtype == 1 then
        local orig_val, resp_val
        if orig_data and orig_data.questions[1] then
            orig_val = orig_data.questions[1].type
        end
        if resp_data and resp_data.questions[1] then
            resp_val = resp_data.questions[1].type
        end
        local result = compare_val("qtype", orig_val, resp_val)
        if result then
            table.insert(results, result)
        end
    end
    if matchcfg.qname == 1 then
        local orig_val, resp_val
        if orig_data and orig_data.questions[1] then
            orig_val = orig_data.questions[1].label
        end
        if resp_data and resp_data.questions[1] then
            resp_val = resp_data.questions[1].label
        end
        local result = compare_val("qname", orig_val, resp_val)
        if result then
            table.insert(results, result)
        end
    end
    -- TODO qcase
    if matchcfg.flags == 1 then
        local result = compare_val("flags", orig_data.flags_str, resp_data.flags_str)
        if result then
            table.insert(results, result)
        end
    end
    if matchcfg.rcode == 1 then
        local result = compare_val("rcode", orig.rcode, resp.rcode)
        if result then
            table.insert(results, result)
        end
    end
    if matchcfg.question == 1 then
        local results2 = compare_rrs_label("question", orig_data.questions, resp_data.questions)
        local result
        for _, result in pairs(results2) do
            table.insert(results, result)
        end
    end
    if matchcfg.answer == 1 or matchcfg.ttl == 1 then
        local results2 = compare_rrs_label("answer", orig_data.answers, resp_data.answers)
        local result
        for _, result in pairs(results2) do
            table.insert(results, result)
        end
    end
    if matchcfg.answertypes == 1 or matchcfg.ttl == 1 then
        local results2 = compare_rrs_type("answertypes", orig_data.answers, resp_data.answers)
        local result
        for _, result in pairs(results2) do
            table.insert(results, result)
        end
    end
    -- TODO answerrrsigs
    if matchcfg.authority == 1 then
        local results2 = compare_rrs_label("authority", orig_data.authorities, resp_data.authorities)
        local result
        for _, result in pairs(results2) do
            table.insert(results, result)
        end
    end
    if matchcfg.additional == 1 then
        local results2 = compare_rrs_label("additional", orig_data.additionals, resp_data.additionals)
        local result
        for _, result in pairs(results2) do
            table.insert(results, result)
        end
    end
    -- TODO edns
    -- TODO nsid

    return results
end

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
clipayload.obj_type = object.CORE_OBJECT_PAYLOAD
local cliobject = ffi.cast("core_object_t*", clipayload)

local respdiff, resprecv, respctx, query_payload, original_payload, response_payload, query_payload_obj
if getopt:val("respdiff") > "" then
    if getopt:val("respdiff-origname") == "" or getopt:val("respdiff-recvname") == "" then
        print("To use respdiff both server names for original (--respdiff-origname) and")
        print("received responses (--respdiff-recvname) must be specified!")
        os.exit(1)
    end
    respdiff = require("dnsjit.output.respdiff").new(getopt:val("respdiff"), getopt:val("respdiff-origname"), getopt:val("respdiff-recvname"))
    resprecv, respctx = respdiff:receive()
    query_payload, original_payload, response_payload = ffi.new("core_object_payload_t"), ffi.new("core_object_payload_t"), ffi.new("core_object_payload_t")
    query_payload.obj_type = object.CORE_OBJECT_PAYLOAD
    original_payload.obj_type = object.CORE_OBJECT_PAYLOAD
    response_payload.obj_type = object.CORE_OBJECT_PAYLOAD
    query_payload_obj = ffi.cast("core_object_t*", query_payload)
    query_payload.obj_prev = ffi.cast("core_object_t*", original_payload)
    original_payload.obj_prev = ffi.cast("core_object_t*", response_payload)
end

if getopt:val("m") then
    print("id", "qname", "qclass", "qtype", "result")
end

local start_sec, start_nsec = clock:realtime()
while true do
    local obj = prod(pctx)
    if obj == nil then
        break
    end
    local dns = require("dnsjit.core.object.dns").new(obj)
    if dns and dns:parse() == 0 then
        local ip, proto, payload = obj, obj, obj:cast()
        while ip ~= nil and ip:type() ~= "ip" and ip:type() ~= "ip6" do
            ip = ip.obj_prev
        end
        while proto ~= nil and proto:type() ~= "udp" and proto:type() ~= "tcp" do
            proto = proto.obj_prev
        end
        if ip ~= nil and proto ~= nil then
            ip = ip:cast()
            proto = proto:cast()
            if dns.qr == 0 then
                local k = string.format("%s %d %s %d", ip:source(), proto.sport, ip:destination(), proto.dport)
                local qname, qtype, qclass
                local n = dns.questions
                if n > 0 and dns:rr_next() == 0 then
                    if dns:rr_ok() == 1 then
                        qname = dns:rr_label()
                        qtype = dns:rr_type()
                        qclass = dns:rr_class()
                    end
                end
                if qname and qtype and qclass then
                    local q = {
                        id = dns.id,
                        qname = qname,
                        qtype = qtype,
                        qclass = qclass,
                        proto = proto:type(),
                        payload = ffi.new("uint8_t[?]", payload.len),
                        len = tonumber(payload.len)
                    }
                    ffi.copy(q.payload, payload.payload, payload.len)
                    queries[k] = q
                end
            else
                local k = string.format("%s %d %s %d", ip:destination(), proto.dport, ip:source(), proto.sport)
                local q = queries[k]
                if q then
                    queries[k] = nil
                    clipayload.payload = q.payload
                    clipayload.len = q.len

                    local responses, response = {}, nil
                    if q.proto == "udp" then
                        if not udpcli then
                            udpcli = require("dnsjit.output.udpcli").new()
                            udpcli:connect(host, port)
                            udprecv, udpctx = udpcli:receive()
                            udpprod, _ = udpcli:produce()
                        end
                        udprecv(udpctx, cliobject)
                        while response == nil do
                            response = udpprod(udpctx)
                        end
                        while response ~= nil do
                            table.insert(responses, response)
                            response = udpprod(udpctx)
                        end
                    elseif q.proto == "tcp" then
                        if not tcpcli then
                            tcpcli = require("dnsjit.output.tcpcli").new()
                            tcpcli:connect(host, port)
                            tcprecv, tcpctx = tcpcli:receive()
                            tcpprod, _ = tcpcli:produce()
                        end
                        tcprecv(tcpctx, cliobject)
                        while response == nil do
                            response = tcpprod(tcpctx)
                        end
                        while response ~= nil do
                            table.insert(responses, response)
                            response = tcpprod(tcpctx)
                        end
                    end

                    local results, dns_response
                    for _, response in pairs(responses) do
                        dns_response = require("dnsjit.core.object.dns").new(response)
                        if dns_response and dns_response:parse() == 0 and dns_response.id == q.id then
                            if getopt:val("m") then
                                results = match(dns, dns_response)
                            end

                            if respdiff then
                                query_payload.payload = q.payload
                                query_payload.len = q.len
                                original_payload.payload = payload.payload
                                original_payload.len = payload.len
                                response = response:cast()
                                response_payload.payload = response.payload
                                response_payload.len = response.len

                                resprecv(respctx, query_payload_obj)
                            end

                            break
                        end
                    end
                    if getopt:val("m") then
                        if results[1] then
                            print(dns.id, q.qname, q.qclass, q.qtype, "failed")
                            for _, v in pairs(results) do
                                print("", v)
                            end
                        else
                            print(dns.id, q.qname, q.qclass, q.qtype, "ok")
                        end
                    end
                end
            end
        end
    end
end
local end_sec, end_nsec = clock:realtime()
if respdiff then
    respdiff:commit(start_sec, end_sec)
end

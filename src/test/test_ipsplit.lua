-- Test cases for dnsjit.filter.ipsplit
-- Some checks that use ip_pkt() assume little-endian machine and will fail otherwise
local ffi = require("ffi")
local object = require("dnsjit.core.objects")
local dns = require("dnsjit.core.object.dns").new()

local function dns_msgid(obj)
    local obj = ffi.cast("core_object_t*", obj)
    assert(obj, "obj is nil")
    local pl = obj:cast()
    assert(obj:type() == "payload" and pl.len > 0, "obj doesn't have payload")
    dns.obj_prev = obj
    dns:parse_header()
    return dns.id
end

local function ip_pkt(obj)
    local obj = ffi.cast("core_object_t*", obj)
    assert(obj, "obj is nil")
    local pl = obj:cast()
    assert(obj:type() == "payload" and pl.len > 0, "obj doesn't have payload")

    local pkt = obj.obj_prev
    while pkt ~= nil do
        if pkt.obj_type == object.IP or pkt.obj_type == object.IP6 then
            return pkt:cast()
        end
        pkt = pkt.obj_prev
    end
    assert(pkt, "obj has no ip/ip6 layer")
end


-----------------------------------------------------
--        pellets.pcap: client detection
--
-- All packets have IPv6 layer and are expected to
-- be sucessfully processed by ipsplit filter.
-- Clients should be identified from source ip.
-----------------------------------------------------
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local copy = require("dnsjit.filter.copy").new()
local ipsplit = require("dnsjit.filter.ipsplit").new()
local out1 = require("dnsjit.core.channel").new(256)
local out2 = require("dnsjit.core.channel").new(256)

input:open_offline("pellets.pcap-dist")
layer:producer(input)
ipsplit:receiver(out1)
ipsplit:receiver(out2)
ipsplit:overwrite_dst()
copy:obj_type(object.IP)
copy:obj_type(object.IP6)
copy:obj_type(object.PAYLOAD)
copy:receiver(ipsplit)

local prod, pctx = layer:produce()
local recv, rctx = copy:receive()

-- Process entire PCAP first, channels are large enough to bufer all packets
while true do
    local obj = prod(pctx)
    if obj == nil then break end
    recv(rctx, obj)
end
out1:close()
out2:close()

assert(ipsplit:discarded() == 0, "some valid packets have been discarded")
assert(out1:size() == 47, "out1: some IPv6 packets lost by filter")
assert(out2:size() == 44, "out2: some IPv6 packets lost by filter")

-- out1: test individual packets
local i = 0
while true do
    local obj = out1:get()
    if obj == nil then break end
    i = i + 1

    if i == 1 then
        assert(dns_msgid(obj) == 0x0a31, "pkt 1: client 1, pkt 1 -> out1")
        assert(ip_pkt(obj):source() == "2001:0db8:beef:feed:0000:0000:0000:0003")
        if ffi.abi("be") then
            assert(ip_pkt(obj):destination() == "0000:0001:0000:0000:0000:0000:0000:0001")
        else
            assert(ip_pkt(obj):destination() == "0100:0000:0000:0000:0000:0000:0000:0001")
        end
    end
    if i == 2 then
        assert(dns_msgid(obj) == 0xb3e8, "pkt 3: client 3, pkt 1 -> out1")
        assert(ip_pkt(obj):source() == "2001:0db8:beef:feed:0000:0000:0000:0005")
        if ffi.abi("be") then
            assert(ip_pkt(obj):destination() == "0000:0002:0000:0000:0000:0000:0000:0001")
        else
            assert(ip_pkt(obj):destination() == "0200:0000:0000:0000:0000:0000:0000:0001")
        end
    end
    if i == 3 then
        assert(dns_msgid(obj) == 0xb3e9, "pkt 4: client 3, pkt 2 -> out1")
        assert(ip_pkt(obj):source() == "2001:0db8:beef:feed:0000:0000:0000:0005")
        if ffi.abi("be") then
            assert(ip_pkt(obj):destination() == "0000:0002:0000:0000:0000:0000:0000:0001")
        else
            assert(ip_pkt(obj):destination() == "0200:0000:0000:0000:0000:0000:0000:0001")
        end
    end
    if i == 13 then assert(dns_msgid(obj) == 0x4a05, "pkt 16: client 7, pkt 1 -> out1") end
    if i == 14 then assert(dns_msgid(obj) == 0x4a06, "pkt 17: client 7, pkt 2 -> out1") end
end

-- out2: test individual packets
local i = 0
while true do
    local obj = out2:get()
    if obj == nil then break end
    i = i + 1

    if i == 1 then
        assert(dns_msgid(obj) == 0xe6bd, "pkt 2: client 2, pkt 1 -> out2")
        assert(ip_pkt(obj):source() == "2001:0db8:beef:feed:0000:0000:0000:0004")
        assert(ip_pkt(obj):destination() == "0100:0000:0000:0000:0000:0000:0000:0001")
    end
    if i == 4 then assert(dns_msgid(obj) == 0xabfe, "pkt 18: client 8, pkt 1 -> out2") end
    if i == 5 then assert(dns_msgid(obj) == 0xabff, "pkt 21: client 8, pkt 2 -> out2") end
end


-----------------------------------------------------
--   pellets.pcap: weighted ipsplit:sequential()
--
-- Test sequential client assignment that respects
-- weight.
-----------------------------------------------------
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local copy = require("dnsjit.filter.copy").new()
local ipsplit = require("dnsjit.filter.ipsplit").new()
local out1 = require("dnsjit.core.channel").new(256)
local out2 = require("dnsjit.core.channel").new(256)

input:open_offline("pellets.pcap-dist")
layer:producer(input)
ipsplit:receiver(out1, 3)
ipsplit:receiver(out2, 2)
copy:obj_type(object.IP)
copy:obj_type(object.IP6)
copy:obj_type(object.PAYLOAD)
copy:receiver(ipsplit)

local prod, pctx = layer:produce()
local recv, rctx = copy:receive()

-- Process entire PCAP first, channels are large enough to bufer all packets
while true do
    local obj = prod(pctx)
    if obj == nil then break end
    recv(rctx, obj)
end
out1:close()
out2:close()

assert(ipsplit:discarded() == 0, "some valid packets have been discarded")
assert(out1:size() + out2:size() == 91, "some IPv6 packets lost by filter")

-- out1: test individual packets
local i = 0
while true do
    local obj = out1:get()
    if obj == nil then break end
    i = i + 1

    if i == 1 then
        assert(dns_msgid(obj) == 0x0a31, "pkt 1: client 1, pkt 1 -> out1")
        assert(ip_pkt(obj):source() == "2001:0db8:beef:feed:0000:0000:0000:0003")
        assert(ip_pkt(obj):destination() == "0000:0000:0000:0000:0000:0000:0000:0001")
    end
    if i == 2 then assert(dns_msgid(obj) == 0xe6bd, "pkt 2: client 2, pkt 1 -> out1") end
    if i == 3 then assert(dns_msgid(obj) == 0xb3e8, "pkt 3: client 3, pkt 1 -> out1") end
    if i == 4 then assert(dns_msgid(obj) == 0xb3e9, "pkt 4: client 3, pkt 2 -> out1") end
    if i == 5 then assert(dns_msgid(obj) == 0x0a6f, "pkt 9: client 6, pkt 1 -> out1") end
end

-- out2: test individual packets
local i = 0
while true do
    local obj = out2:get()
    if obj == nil then break end
    i = i + 1

    if i == 1 then assert(dns_msgid(obj) == 0xaac6, "pkt 5: client 4, pkt 1 -> out2") end
    if i == 2 then assert(dns_msgid(obj) == 0xaea6, "pkt 6: client 5, pkt 1 -> out2") end
    if i == 3 then assert(dns_msgid(obj) == 0xaea7, "pkt 7: client 5, pkt 2 -> out2") end
end

-----------------------------------------------------
--   pellets.pcap: weighted ipsplit:random()
--
-- Test sequential client assignment that respects
-- weight.
-----------------------------------------------------
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local copy = require("dnsjit.filter.copy").new()
local ipsplit = require("dnsjit.filter.ipsplit").new()
local out1 = require("dnsjit.core.channel").new(256)
local out2 = require("dnsjit.core.channel").new(256)

input:open_offline("pellets.pcap-dist")
layer:producer(input)
ipsplit:receiver(out1, 85)
ipsplit:receiver(out2, 15)
ipsplit:random()
copy:obj_type(object.IP)
copy:obj_type(object.IP6)
copy:obj_type(object.PAYLOAD)
copy:receiver(ipsplit)

local prod, pctx = layer:produce()
local recv, rctx = copy:receive()

-- Process entire PCAP first, channels are large enough to bufer all packets
while true do
    local obj = prod(pctx)
    if obj == nil then break end
    recv(rctx, obj)
end
out1:close()
out2:close()

assert(ipsplit:discarded() == 0, "some valid packets have been discarded")
assert(out1:size() == 81, "out1: some IPv6 packets lost by filter")
assert(out2:size() == 10, "out2: some IPv6 packets lost by filter")

-- out1: test individual packets
local i = 0
while true do
    local obj = out1:get()
    if obj == nil then break end
    i = i + 1
    if i == 1 then assert(dns_msgid(obj) == 0xe6bd, "pkt 1: client 2, pkt 1 -> out1") end
    if i == 2 then assert(dns_msgid(obj) == 0xb3e8, "pkt 2: client 3, pkt 1 -> out1") end
    if i == 3 then assert(dns_msgid(obj) == 0xb3e9, "pkt 3: client 3, pkt 2 -> out1") end
    if i == 5 then assert(dns_msgid(obj) == 0xaea6, "pkt 4: client 5, pkt 1 -> out1") end
    if i == 29 then assert(dns_msgid(obj) == 0xaeaf, "pkt 29: client 5, pkt 10 -> out1") end
end

-- out2: test individual packets
local i = 0
while true do
    local obj = out2:get()
    if obj == nil then break end
    i = i + 1
    if i == 1 then assert(dns_msgid(obj) == 0x0a31, "pkt 1: client 1, pkt 1 -> out2") end
    if i == 2 then assert(dns_msgid(obj) == 0x0a6f, "pkt 2: client 6, pkt 1 -> out2") end
    if i == 10 then assert(dns_msgid(obj) == 0x0a70, "pkt 10: client 6, pkt 2 -> out2") end
end

-----------------------------------------------------
--        Tests with dns.pcap
--
-- Packets use IPv4 and not all packets have IP layer
-----------------------------------------------------
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local copy = require("dnsjit.filter.copy").new()
local ipsplit = require("dnsjit.filter.ipsplit").new()
local out1 = require("dnsjit.core.channel").new(256)
local out2 = require("dnsjit.core.channel").new(256)

input:open_offline("dns.pcap-dist")
layer:producer(input)
ipsplit:receiver(out1)
ipsplit:receiver(out2)
ipsplit:overwrite_src()
copy:obj_type(object.IP)
copy:obj_type(object.IP6)
copy:obj_type(object.PAYLOAD)
copy:receiver(ipsplit)

local prod, pctx = layer:produce()
local recv, rctx = copy:receive()

-- Process entire PCAP first, channels are large enough to bufer all packets
while true do
    local obj = prod(pctx)
    if obj == nil then break end
    recv(rctx, obj)
end
out1:close()
out2:close()

assert(out1:size() + out2:size() == 123, "some IPv4 packets lost by filter")

-- out1: test individual packets
local i = 0
while true do
    local obj = out1:get()
    if obj == nil then break end
    i = i + 1
    if i == 1 then
        assert(dns_msgid(obj) == 0xe7af)
        if ffi.abi("be") then
            assert(ip_pkt(obj):source() == "0.0.0.1")
        else
            assert(ip_pkt(obj):source() == "1.0.0.0")
        end
        assert(ip_pkt(obj):destination() == "8.8.8.8")
    end
end

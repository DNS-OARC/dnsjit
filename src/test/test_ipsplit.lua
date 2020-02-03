-- Test cases for dnsjit.filter.ipsplit
local ffi = require("ffi")
local object = require("dnsjit.core.objects")
local dns = require("dnsjit.core.object.dns").new()

local function check_dns_msgid(obj, msgid, errmsg)
    local obj = ffi.cast("core_object_t*", obj)
    assert(obj, errmsg)
    local pl = obj:cast()
    assert(obj:type() == "payload" and pl.len > 0, errmsg)
    dns.obj_prev = obj
    dns:parse_header()
    assert(dns.id == msgid, errmsg)
end
-----------------------------------------------------
--        Tests with pellets.pcap
--
-- All packets have IPv6 layer and are expected to
-- be sucessfully processed by ipsplit filter.
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

    if i == 1 then check_dns_msgid(obj, 0x0a31, "pkt 1: client 1, pkt 1 -> out1") end
    if i == 2 then check_dns_msgid(obj, 0xb3e8, "pkt 3: client 3, pkt 1 -> out1") end
    if i == 3 then check_dns_msgid(obj, 0xb3e9, "pkt 4: client 3, pkt 2 -> out1") end
    if i == 13 then check_dns_msgid(obj, 0x4a05, "pkt 16: client 7, pkt 1 -> out1") end
    if i == 14 then check_dns_msgid(obj, 0x4a06, "pkt 17: client 7, pkt 2 -> out1") end
end

-- out2: test individual packets
local i = 0
while true do
    local obj = out2:get()
    if obj == nil then break end
    i = i + 1

    if i == 1 then check_dns_msgid(obj, 0xe6bd, "pkt 2: client 2, pkt 1 -> out2") end
    if i == 4 then check_dns_msgid(obj, 0xabfe, "pkt 18: client 8, pkt 1 -> out2") end
    if i == 5 then check_dns_msgid(obj, 0xabff, "pkt 21: client 8, pkt 2 -> out2") end
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

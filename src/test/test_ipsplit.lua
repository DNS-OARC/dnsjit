-- Test cases for dnsjit.filter.ipsplit

-----------------------------------------------------
--        Tests with pellets.pcap
--
-- All packets have IPv6 layer and are expected to
-- be sucessfully processed by ipsplit filter.
-----------------------------------------------------
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local ipsplit = require("dnsjit.filter.ipsplit").new()
local out1 = require("dnsjit.output.null").new()
local out2 = require("dnsjit.output.null").new()

input:open_offline("pellets.pcap-dist")
layer:producer(input)
ipsplit:receiver(out1)
ipsplit:receiver(out2)

local prod, pctx = layer:produce()
local recv, rctx = ipsplit:receive()

-- Check initial state
assert(out1:packets() == 0)
assert(out2:packets() == 0)

local i = 1
while true do
    local obj = prod(pctx)
    if obj == nil then break end
    recv(rctx, obj)

    -- Check packet processing
    if i == 1 then assert(out1:packets() == 1, "pkt 1: not assigned to out1") end
    if i == 2 then assert(out2:packets() == 1, "pkt 2: not assigned to out2") end
    if i == 3 then assert(out1:packets() == 2, "pkt 3: not assigned to out1") end
    if i == 4 then assert(out1:packets() == 3, "pkt 4: same client not detected") end

    i = i + 1
end

-- Post-processing test cases for pellets.pcap
assert(ipsplit:discarded() == 0, "some valid packets have been discarded")
assert(out1:packets() + out2:packets() == 91, "some IPv6 packets lost by filter")

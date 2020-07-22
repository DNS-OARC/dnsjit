#!/usr/bin/env dnsjit
-- count-pkts-per-ip.lua: count number of packets received from each IP/IPv6 address

local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local ip = require("dnsjit.core.object.ip")
local ip6 = require("dnsjit.core.object.ip6")
local trie = require("dnsjit.lib.trie").new("uint64_t", true)
local getopt = require("dnsjit.lib.getopt").new({})

local pcap = unpack(getopt:parse())
if pcap == nil then
    print("usage: "..arg[1].." <pcap>")
end

-- Set up input
input:open_offline(pcap)
layer:producer(input)
local produce, pctx = layer:produce()

-- Read input and count packets
while true do
	local obj = produce(pctx)
	if obj == nil then break end
    local pkt = obj:cast_to(object.IP) or obj:cast_to(object.IP6)

    if pkt ~= nil then
        local iplen = 4
        if pkt:type() == "ip6" then
            iplen = 16
        end

        local node = trie:get_ins(pkt.src, iplen)
        node:set(node:get() + 1)
    end
end

-- Print statistics
local iter = trie:iter()
local node = iter:node()

while node ~= nil do
    local npkts = tonumber(node:get())
    local ipstr
    local key, keylen = node:key()
    if keylen == 4 then
        ipstr = ip.tostring(key)
    elseif keylen == 16 then
        ipstr = ip6.tostring(key, true)
    end

    print(ipstr.." sent "..npkts.." packets")
    iter:next()
    node = iter:node()
end

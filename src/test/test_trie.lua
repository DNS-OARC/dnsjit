-- Test cases for dnsjit.lib.trie

local function key_compare(node1, node2)
    local key1, keylen1 = node1:key()
    local key2, keylen2 = node2:key()
    if keylen1 ~= keylen2 then return false end
    for i = 0, keylen1 - 1 do
        if key1[i] ~= key2[i] then return false end
    end
    return true
end

-----------------------------------------------------
--    binary-key trie with which stores numbers
-----------------------------------------------------
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local ip6 = require("dnsjit.core.object.ip6")
local trie = require("dnsjit.lib.trie").new("uint32_t", true, 16)

input:open_offline("pellets.pcap-dist")
layer:producer(input)

local prod, pctx = layer:produce()

-- fill trie with values
while true do
	local obj = prod(pctx)
	if obj == nil then break end
    local pkt = obj:cast_to(object.IP6)

    if pkt ~= nil then
        -- count number of packets per IP
        local node = trie:get_ins(pkt.src)
        node:set(node:get() + 1)
    end
end

assert(trie:weight() == 29)

-- test iterator and check values
local iter = trie:iter()
local node = iter:node()
local npkts = 0

local i = 0
while node ~= nil do
    i = i + 1
    local ip6str = ip6.tostring(node:key())
    local val = tonumber(node:get())
    npkts = npkts + val

    if i == 1 then assert(ip6str == "2001:0db8:beef:feed:0000:0000:0000:0003" and val == 1) end
    if i == 1 then
        local first = trie:get_first()
        assert(key_compare(node, first))
        assert(node:get() == first:get())
    end
    if i == 2 then assert(ip6str == "2001:0db8:beef:feed:0000:0000:0000:0004" and val == 1) end
    if i == 2 then
        local second = trie:get_try(node:key())
        assert(key_compare(node, second))
        assert(node:get() == second:get())
    end
    if i == 5 then assert(ip6str == "2001:0db8:beef:feed:0000:0000:0000:0008" and val == 10) end
    if i == 29 then assert(ip6str == "2001:0db8:beef:feed:0000:0000:0000:0042" and val == 1) end

    iter:next()
    node = iter:node()
end

assert(npkts == 91)

trie:clear()
assert(trie:weight() == 0)


-----------------------------------------------------
--    string-key trie with which stores objects
-----------------------------------------------------
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local ip6 = require("dnsjit.core.object.ip6")
local trie = require("dnsjit.lib.trie").new("core_object_t*")

input:open_offline("dns.pcap-dist")
layer:producer(input)

local prod, pctx = layer:produce()

-- fill trie with values
while true do
	local obj = prod(pctx)
	if obj == nil then break end
    local pkt = obj:cast_to(object.IP)

    if pkt ~= nil then
        local node = trie:get_ins(pkt:source())
        local pkt2 = node:get()
        if val ~= nil then
            val:free()
        end
        node:set(pkt:copy():uncast())
    end
end

assert(trie:weight() == 3)

local node
node = trie:get_first()
assert(node:key() == "172.17.0.10")
pkt = node:get():cast()
assert(pkt:source() == "172.17.0.10")
assert(pkt.id == 0x538b)
node, exact = trie:get_leq("172.17.0.10")
assert(exact == 0)
assert(node:key() == "172.17.0.10")
pkt:free()

node = trie:get_try("8.8.8.8")
assert(node:key() == "8.8.8.8")
pkt = node:get():cast()
assert(pkt:source() == "8.8.8.8")
pkt:free()

node = trie:get_try("216.58.218.206")
assert(node:key() == "216.58.218.206")
pkt = node:get():cast()
assert(pkt:source() == "216.58.218.206")
pkt:free()

node = trie:get_try("nonexistent")
assert(node == nil)

node = trie:get_leq("172.17.0.10", 2)
assert(node == nil)

trie:clear()
assert(trie:weight() == 0)

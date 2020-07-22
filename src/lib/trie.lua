-- Copyright (c) 2020, CZ.NIC, z.s.p.o.
-- All rights reserved.
--
-- This file is part of dnsjit.
--
-- dnsjit is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- dnsjit is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.

-- dnsjit.lib.trie
-- Prefix-tree data structure which addresses values by strings or byte arrays
-- .SS Binary-key trie with integer values
--   local trie = require("dnsjit.lib.trie").new("uint64_t", true, 4)
--   -- assume we have a bunch of dnsjit.core.object.ip packets to process
--   for _, pkt in pairs(pkts) do
--       local node = trie:get_ins(pkt.src)
--       local value = node:get()  -- new nodes' values are initialized to 0
--       node:set(value + 1)
--   end
--   -- iterate over unique IPs and print number of packets received from each
--   local iter = trie:iter()
--   local node = iter:node()
--   local p = require("dnsjit.lib.ip")
--   while node ~= nil do
--       local ip_bytes = node:key()
--       local npkts = tonumber(node:get())
--       print(ip.tostring(ip_bytes).." sent "..npkts.." packets")
--       iter:next()
--       node = iter:node()
--   end
-- .SS String-key trie with cdata values
--   local trie = require("dnsjit.lib.trie").new("core_object_t*")
--   local obj1  -- assume this contains cdata of type core_object_t*
--   local node = trie:get_ins("obj1")
--   node:set(obj1)
--   node = trie:get_try("obj1")
--   assert(node:get() == obj1)
--
-- Fast and scalable data structure that stores values indexed by strings or
-- byte arrays, such as IP addresses. Values of size up to sizeof(size_t) can
-- be stored directly, otherwise a pointer must be used.  This data structure
-- is suitable for high-performance use-cases where lua tables are insufficient.
module(...,package.seeall)

require("dnsjit.lib.trie_h")
local ffi = require("ffi")
local C = ffi.C
local log = require("dnsjit.core.log")
local module_log = log.new("lib.trie")
local TrieNode = require("dnsjit.lib.trie.node")
local TrieIter = require("dnsjit.lib.trie.iter")

Trie = {}

-- Create a new Trie that stores
-- .I ctype
-- values as data.
-- By default, keys are handled as strings.
-- To use trie with byte arrays, set
-- .I binary
-- to true.
-- Optionally,
-- .I keylen
-- may be specified as a default keylen for binary keys.
-- For string keys, their string length is used by default.
function Trie.new(ctype, binary, keylen)
    if ctype == nil then
        module_log:fatal("missing value ctype")
    end
    if ffi.sizeof(ctype) > ffi.sizeof("void *") then
        module_log:fatal("data type exceeds max size, use a pointer instead")
    end
    if keylen ~= nil and not binary then
        module_log:warning("setting keylen has no effect for string-key tries")
    end

    local self = setmetatable({
        obj = C.trie_create(nil),
        _binary = binary,
        _keylen = keylen,
        _ctype = ctype,
        _log = log.new("lib.trie", module_log),
    }, { __index = Trie })

    ffi.gc(self.obj, C.trie_free)

    return self
end

function Trie:_get_keylen(key, keylen)
    if keylen ~= nil then
        if type(keylen) == "number" then
            return keylen
        else
            self._log:fatal("keylen must be numeric")
        end
    end
    if not self._binary then
        if type(key) == "string" then
            return string.len(key)
        else
            self._log:fatal("key must be string when using trie with non-binary keys")
        end
    end
    if not self._keylen or type(self._keylen) ~= "number" then
        self._log:fatal("default keylen not set or invalid")
    end
    return self._keylen
end

-- Return the Log object to control logging of this instance or module.
function Trie:log()
    if self == nil then
        return module_log
    end
    return self._log
end

-- Clear the trie instance (make it empty).
function Trie:clear()
    C.trie_clear(self.obj)
end

-- Return the number of keys in the trie.
function Trie:weight()
    return tonumber(C.trie_weight(self.obj))
end

-- Search the trie and return nil of failure.
function Trie:get_try(key, keylen)
    keylen = self:_get_keylen(key, keylen)
    local val = C.trie_get_try(self.obj, key, keylen)
    if val == nil then return nil end
    val = ffi.cast("trie_val_t *", val)
    return TrieNode.new(self, val, key, keylen)
end

-- Search the trie and insert an empty node (with value set to 0) on failure.
function Trie:get_ins(key, keylen)
    keylen = self:_get_keylen(key, keylen)
    local val = C.trie_get_ins(self.obj, key, keylen)
    val = ffi.cast("trie_val_t *", val)
    return TrieNode.new(self, val, key, keylen)
end

-- Return the first node (minimum).
function Trie:get_first()
    local key_ptr = ffi.new("uint8_t *[1]")
    local keylen_ptr = ffi.new("uint32_t[1]")
    local val = C.trie_get_first(self.obj, key_ptr, keylen_ptr)
    local keylen = tonumber(keylen_ptr[0])
    key = key_ptr[0]
    return TrieNode.new(self, val, key, keylen)
end

-- Return a trie iterator.
-- It is only valid as long as the key-set remains unchanged.
function Trie:iter()
    return TrieIter.new(self)
end

-- dnsjit.lib.trie.node (3), dnsjit.lib.trie.iter (3)
return Trie

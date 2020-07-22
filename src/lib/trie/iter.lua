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

-- dnsjit.lib.trie.iter
-- Iterator of the trie.
-- Beware that iterator is only valid as long as the trie's key-set remains unchanged.
-- .SS Iterate over all trie's key-value pairs
--   local trie = require("dnsjit.lib.trie").new("uint64_t")
--   local iter = trie:iter()
--   local node = iter:node()
--   while node ~= nil do
--       local key = node:key()
--       local value = tonumber(node:get())
--       print(key..": "..value)
--       iter:next()
--       node = iter:node()
--   end
module(...,package.seeall)

require("dnsjit.lib.trie_h")
local ffi = require("ffi")
local C = ffi.C
local log = require("dnsjit.core.log")
local module_log = log.new("lib.trie.iter")
local TrieNode = require("dnsjit.lib.trie.node")

TrieIter = {}

-- Create a new iterator pointing to the first element (if any).
function TrieIter.new(trie)
    local self = setmetatable({
        obj = C.trie_it_begin(trie.obj),
        _trie = trie,
        _log = log.new("lib.trie.iter", module_log),
    }, { __index = TrieIter })

    ffi.gc(self.obj, C.trie_it_free)

    return self
end

-- Return the Log object to control logging of this instance or module.
function TrieIter:log()
    if self == nil then
        return module_log
    end
    return self._log
end

-- Return the node pointer to by the iterator.
-- Returns nil when iterator has gone past the last element.
function TrieIter:node()
    if C.trie_it_finished(self.obj) then
        return nil
    end

    local keylen_ptr = ffi.new("size_t[1]")
    local key = C.trie_it_key(self.obj, keylen_ptr)
    local keylen = tonumber(keylen_ptr[0])

    local val = C.trie_it_val(self.obj)
    return TrieNode.new(self._trie, val, key, keylen)
end

-- Advance the iterator to the next element.
--
-- Iteration is in ascending lexicographical order.
-- Empty string would be considered as the very first.
--
-- You may not use this function if the trie's key-set has been modified during the lifetime of the iterator (modifying only values is OK).
function TrieIter:next()
    C.trie_it_next(self.obj)
end

-- dnsjit.lib.trie (3), dnsjit.lib.trie.node (3)
return TrieIter

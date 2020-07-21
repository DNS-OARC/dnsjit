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

-- dnsjit.lib.trie.node
-- Node of trie, which contains the value and key.
-- .SS Set a node's value.
--      node:set(42)
-- .SS Get a node's key and value.
--      local key = node.key
--      local val = tonumber(node:get())
--
-- .SS Attributes
-- .TP
-- key
-- Key of this node.
-- It is either string or a byte array, depending on the trie's
-- .I binary
-- setting.
-- .TP
-- keylen
-- Length of key content.
module(...,package.seeall)

require("dnsjit.lib.trie_h")
local ffi = require("ffi")
local C = ffi.C
local log = require("dnsjit.core.log")
local module_log = log.new("lib.trie.node")

TrieNode = {}

-- Create a new node object.
function TrieNode.new(trie, val, key, keylen)
    local self = setmetatable({
        key = key,
        keylen = keylen,
        _val = val,
        _trie = trie,
        _log = log.new("lib.trie.node", module_log),
    }, { __index = TrieNode })

    return self
end

-- Return the Log object to control logging of this instance or module.
function TrieNode:log()
    if self == nil then
        return module_log
    end
    return self._log
end

-- Get the value of this node.
function TrieNode:get()
    return ffi.cast(self._trie._ctype, self._val[0])
end

-- Set the value of this node.
function TrieNode:set(value)
    value = ffi.cast('void *', value)
    self._val[0] = value
end

-- dnsjit.lib.trie (3)
return TrieNode

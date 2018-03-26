-- Copyright (c) 2018, OARC, Inc.
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

-- dnsjit.output.udpcli
-- Simple and dumb UDP DNS client
--   local output = require("dnsjit.output.udpcli").new("127.0.0.1", "53")
--
-- Simple and rather dumb DNS client that takes any payload you give it,
-- look for the bit in the payload that says it's a DNS query and sends
-- the full payload over UDP if it is.
module(...,package.seeall)

require("dnsjit.output.udpcli_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_udpcli_t"
local output_udpcli_t = ffi.typeof(t_name)
local Udpcli = {}

-- Create a new Udpcli output to send queries to the
-- .I host
-- and
-- .IR port .
function Udpcli.new(host, port)
    local self = {
        obj = output_udpcli_t(),
    }
    C.output_udpcli_init(self.obj, host, port)
    ffi.gc(self.obj, C.output_udpcli_destroy)
    return setmetatable(self, { __index = Udpcli })
end

-- Return the C functions and context for receiving objects.
function Udpcli:receive()
    return C.output_udpcli_receiver(), self.obj
end

-- Return the number of queries we sent.
function Udpcli:packets()
    return tonumber(self.obj.pkts)
end

-- Return the number of errors when sending.
function Udpcli:errors()
    return tonumber(self.obj.errs)
end

return Udpcli

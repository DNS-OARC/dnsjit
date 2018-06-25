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

-- dnsjit.core.object.ip6
-- An IPv6 packet
--
-- An IPv6 packet that usually can be found in the object chain
-- after parsing with, for example, Layer filter.
-- .SS Attributes
-- .TP
-- flow
-- 4 bits version, 8 bits TC and 20 bits flow-ID.
-- .TP
-- plen
-- Payload length (as in the IPv6 header).
-- .TP
-- nxt
-- Next header.
-- .TP
-- hlim
-- Hop limit.
-- .TP
-- src
-- Source address.
-- .TP
-- dst
-- Destination address.
-- .TP
-- is_frag
-- 1 bit, set if packet is a fragment.
-- .TP
-- have_rtdst
-- 1 bit, set if
-- .I rtdst
-- is set.
-- .TP
-- frag_offlg
-- Offset, reserved, and flag taken from the fragment header.
-- .TP
-- frag_ident
-- Identification taken from the fragment header.
-- .TP
-- rtdst
-- Destination address found in the routing extension header.
-- .TP
-- payload
-- A pointer to the payload.
-- .TP
-- len
-- The length of the payload.
-- .TP
-- pad_len
-- The length of padding found, if any.
module(...,package.seeall)

require("dnsjit.core.object.ip6_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_ip6_t"
local core_object_ip6_t
local Ip6 = {}

-- Return the textual type of the object.
function Ip6:type()
    return "ip6"
end

-- Return the previous object.
function Ip6:prev()
    return self.obj_prev
end

-- Cast the object to the underlining object module and return it.
function Ip6:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Ip6:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Ip6:copy()
    return C.core_object_ip6_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Ip6:free()
    C.core_object_ip6_free(self)
end

function _pretty(ip)
    local src = {}

    local n, nn
    nn = 1
    for n = 0, 15, 2 do
        if ip[n] ~= 0 then
            src[nn] = string.format("%x%02x", ip[n], ip[n + 1])
        elseif ip[n + 1] ~= 0 then
            src[nn] = string.format("%x", ip[n + 1])
        else
            src[nn] = "0"
        end
        nn = nn + 1
    end

    local best_n, best_at, at = 0, 0, 0
    n = 0
    for nn = 1, 8 do
        if src[nn] == "0" then
            if n == 0 then
                at = nn
            end
            n = n + 1
        else
            if n > 0 then
                if n > best_n then
                    best_n = n
                    best_at = at
                end
                n = 0
            end
        end
    end
    if n > 0 then
        if n > best_n then
            best_n = n
            best_at = at
        end
    end
    if best_n > 1 then
        for n = 2, best_n do
            table.remove(src, best_at)
        end
        if best_at == 1 or best_at + best_n > 8 then
            src[best_at] = ":"
        else
            src[best_at] = ""
        end
    end

    return table.concat(src,":")
end

-- Return the IP source as a string. If
-- .I pretty
-- is true then return a easier to read IPv6 address.
function Ip6:source(pretty)
    if pretty == true then
        return _pretty(self.src)
    end
    return string.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        self.src[0], self.src[1], self.src[2], self.src[3],
        self.src[4], self.src[5], self.src[6], self.src[7],
        self.src[8], self.src[9], self.src[10], self.src[11],
        self.src[12], self.src[13], self.src[14], self.src[15])
end

-- Return the IP destination as a string. If
-- .I pretty
-- is true then return a easier to read IPv6 address.
function Ip6:destination(pretty)
    if pretty == true then
        return _pretty(self.dst)
    end
    return string.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        self.dst[0], self.dst[1], self.dst[2], self.dst[3],
        self.dst[4], self.dst[5], self.dst[6], self.dst[7],
        self.dst[8], self.dst[9], self.dst[10], self.dst[11],
        self.dst[12], self.dst[13], self.dst[14], self.dst[15])
end

core_object_ip6_t = ffi.metatype(t_name, { __index = Ip6 })

-- dnsjit.core.object (3),
-- dnsjit.filter.layer (3)
return Ip6

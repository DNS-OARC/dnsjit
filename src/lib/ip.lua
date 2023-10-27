-- Copyright (c) 2018-2024 OARC, Inc.
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

-- dnsjit.lib.ip
-- IP address utility library
--   local ip = require("dnsjit.lib.ip")
--   print(ip.ipstring(ipv4_cdata))
--   print(ip.ip6string(ipv6_cdata), true)
--
-- A library to help with various IP address related tasks, such as
-- printing them.
module(...,package.seeall)

local ffi = require("ffi")

Ip = {}

-- Return an IPv4 or IPv6 address as a string.
-- If it's an IPv6 address the optional argument
-- .I pretty
-- is true then return an easier to read IPv6 address.
-- Return an empty string on invalid input.
function Ip.tostring(ip, pretty)
    if type(ip) == "cdata" then
        if ffi.sizeof(ip) == 4 then
            return Ip.ipstring(ip)
        elseif ffi.sizeof(ip) == 16 then
            return Ip.ip6string(ip, pretty)
        end
    end
    return ""
end

-- Return a IPv4 address as a string.
-- The input is a 4-byte cdata array.
function Ip.ipstring(ip)
    return ip[0] ..".".. ip[1] ..".".. ip[2] ..".".. ip[3]
end

local function _pretty(ip)
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

-- Return the IPv6 address as a string.
-- The input is a 16-byte cdata array.
-- If
-- .I pretty
-- is true then return an easier to read IPv6 address.
function Ip.ip6string(ip6, pretty)
    if pretty == true then
        return _pretty(ip6)
    end
    return string.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7],
        ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15])
end

-- dnsjit.core.object.ip (3),
-- dnsjit.core.object.ip6 (3)
return Ip

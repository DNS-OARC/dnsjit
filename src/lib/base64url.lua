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

-- dnsjit.lib.base64url
-- Utility library to convert data to base64url format
--   local base64url = require("dnsjit.lib.base64url")
-- .SS Encoding and decoding lua strings
--   local encoded = base64url.encode("abcd")
--   local decoded = base64url.decode(encoded)
-- .SS Encoding C byte arrays
--   local pl  -- pl is core.object.payload
--   local encoded = base64url.encode(pl.payload, pl.len)
--
-- Encode and decode data to/from base64url format.
module(...,package.seeall)

require("dnsjit.lib.base64url_h")
local ffi = require("ffi")
local C = ffi.C
local log = require("dnsjit.core.log")
local module_log = log.new("lib.base64url")

Base64Url = {}

-- Encode lua string or C byte array to base64url representation.
-- The input string may contain non-printable characters.
--
-- .B data_len
-- is length of the input data. Optional for lua strings, required for C byte arrays.
function Base64Url.encode(data, data_len)
    data_len = tonumber(data_len)  -- in case of cdata length
    if type(data) == "cdata" then
        if type(data_len) ~= "number" then
            module_log:fatal("encode: data_len must be specified for cdata")
            return
        end
    elseif type(data) ~= "string" then
        module_log:fatal("encode: input must be string")
        return
    end

    if data_len ~= nil and data_len < 0 then
        module_log:fatal("encode: data_len must be greater than 0")
        return
    end

    local in_len = data_len or string.len(data)
    local buf_len = math.ceil(4 * in_len / 3) + 2
    local buf = ffi.new("uint8_t[?]", buf_len)
    local out_len = ffi.C.base64url_encode(data, in_len, buf, buf_len)
    if out_len < 0 then
        module_log:critical("encode: error ("..log.errstr(-out_len)..")")
        return
    end
    return ffi.string(buf, out_len)
end

-- Decode a base64url encoded lua string.
-- The output string may contain non-printable characters.
function Base64Url.decode(data)
    if type(data) ~= "string" then
        module_log:fatal("decode: input must be string")
        return
    end

    local in_len = string.len(data)
    local buf_len = math.ceil(3 * in_len / 4) + 1
    local buf = ffi.new("uint8_t[?]", buf_len)
    local out_len = ffi.C.base64url_decode(data, in_len, buf, buf_len)
    if out_len == -34 then  -- ERANGE
        module_log:critical("decode: error "..log.errstr(-out_len).." - invalid character(s) in input string?")
        return
    elseif out_len < 0 then
        module_log:critical("decode: error "..log.errstr(-out_len))
        return
    end
    return ffi.string(buf, out_len)
end

-- dnsjit.core.object.payload(3)
-- dnsjit.output.dnssim (3)
return Base64Url

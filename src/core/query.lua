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

-- dnsjit.core.query
-- Container of a DNS query/response
-- TODO
--
-- TODO
module(...,package.seeall)

local ch = require("dnsjit.core.chelpers")
local log = require("dnsjit.core.log")
require("dnsjit.core.query_h")
local ffi = require("ffi")
local C = ffi.C

local Query = {}

function Query.new(o)
    if o == nil then
        o = C.query_new()
    elseif not ffi.istype("query_t", o) then
        error("is not query_t")
    end
    ffi.gc(o, C.query_free)
    local log = log.new(o.log)
    log:debug("new()")
    return setmetatable({
        _ = o,
        log = log,
    }, {__index = Query})
end

function Query:struct()
    self.log:debug("struct()")
    return self._
end

function Query:parse_header()
    return ch.z2n(C.query_parse_header(self._))
end

function Query:parse()
    return ch.z2n(C.query_parse(self._))
end

function Query:src()
    return ffi.string(C.query_src(self._))
end

function Query:dst()
    return ffi.string(C.query_dst(self._))
end

function Query:sport()
    return self._.sport
end

function Query:dport()
    return self._.dport
end

function Query:have_id()
    return self._.have_id
end

function Query:have_qr()
    return self._.have_qr
end

function Query:have_opcode()
    return self._.have_opcode
end

function Query:have_aa()
    return self._.have_aa
end

function Query:have_tc()
    return self._.have_tc
end

function Query:have_rd()
    return self._.have_rd
end

function Query:have_ra()
    return self._.have_ra
end

function Query:have_z()
    return self._.have_z
end

function Query:have_ad()
    return self._.have_ad
end

function Query:have_cd()
    return self._.have_cd
end

function Query:have_rcode()
    return self._.have_rcode
end

function Query:have_qdcount()
    return self._.have_qdcount
end

function Query:have_ancount()
    return self._.have_ancount
end

function Query:have_nscount()
    return self._.have_nscount
end

function Query:have_arcount()
    return self._.have_arcount
end

function Query:id()
    return self._.id
end

function Query:qr()
    return self._.qr
end

function Query:opcode()
    return self._.opcode
end

function Query:aa()
    return self._.aa
end

function Query:tc()
    return self._.tc
end

function Query:rd()
    return self._.rd
end

function Query:ra()
    return self._.ra
end

function Query:z()
    return self._.z
end

function Query:ad()
    return self._.ad
end

function Query:cd()
    return self._.cd
end

function Query:rcode()
    return self._.rcode
end

function Query:qdcount()
    return self._.qdcount
end

function Query:ancount()
    return self._.ancount
end

function Query:nscount()
    return self._.nscount
end

function Query:arcount()
    return self._.arcount
end

function Query:questions()
    return self._.questions
end

function Query:answers()
    return self._.answers
end

function Query:authorities()
    return self._.authorities
end

function Query:additionals()
    return self._.additionals
end

function Query:rr_next()
    return C.query_rr_next(self._)
end

function Query:rr_ok()
    return C.query_rr_ok(self._)
end

function Query:rr_label()
    local ptr = C.query_rr_label(self._)
    if ptr == nil then
        return ""
    end
    return ffi.string(ptr)
end

function Query:rr_type()
    return C.query_rr_type(self._)
end

function Query:rr_class()
    return C.query_rr_class(self._)
end

function Query:rr_ttl()
    return C.query_rr_ttl(self._)
end

return Query

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
-- Container of a DNS message and related capturing information
--   local query = require("dnsjit.core.query")
--   local q = query.new()
--   print(q:src(), q:dst(), q:id())
--
-- The core object that is passed between receiver and receivee and describes
-- a DNS message, how it was captured or generated.
-- .LP
-- .B NOTE
-- it is not common to create this object, it is received from other modules.
module(...,package.seeall)

local ch = require("dnsjit.core.chelpers")
require("dnsjit.core.query_h")
local ffi = require("ffi")
local C = ffi.C

local Query = {}

-- Create a new query or bind an existing
-- .IR query_t .
function Query.new(o)
    if o == nil then
        o = C.query_new()
    elseif not ffi.istype("query_t", o) then
        error("is not query_t")
    end
    ffi.gc(o, C.query_free)
    return setmetatable({
        _ = o,
    }, {__index = Query})
end

-- Return the Log object to control logging of this instance or module.
function Query:log()
    if self == nil then
        return C.query_log()
    end
    return self._._log
end

-- Return the
-- .I query_t
-- C structure bound to this object.
function Query:struct()
    self._._log:debug("struct()")
    return self._
end

-- Parse the DNS headers or the query.
function Query:parse_header()
    return ch.z2n(C.query_parse_header(self._))
end

-- Parse the full DNS message or just the body if the header was already parsed.
function Query:parse()
    return ch.z2n(C.query_parse(self._))
end

-- Return the IP source as a string.
function Query:src()
    return ffi.string(C.query_src(self._))
end

-- Return the IP destination as a string.
function Query:dst()
    return ffi.string(C.query_dst(self._))
end

-- Return or set the source ID, used to track the unique source of the
-- query.
-- See also
-- .BR dnsjit.core.tracking (3).
function Query:sid(sid)
    if sid == nil then
        return self._.sid
    end
    self._.sid = sid
end

-- Return or set the query ID, used to track the unique query from a
-- source.
-- See also
-- .BR dnsjit.core.tracking (3).
function Query:qid(qid)
    if qid == nil then
        return self._.qid
    end
    self._.qid = qid
end

-- Return the source port.
function Query:sport()
    return self._.sport
end

-- Return the destination port.
function Query:dport()
    return self._.dport
end

-- Return true if there is a DNS ID.
function Query:have_id()
    return ch.i2b(self._.have_id)
end

-- Return true if there is a QR flag.
function Query:have_qr()
    return ch.i2b(self._.have_qr)
end

-- Return true if there is an OPCODE.
function Query:have_opcode()
    return ch.i2b(self._.have_opcode)
end

-- Return true if there is a AA flag.
function Query:have_aa()
    return ch.i2b(self._.have_aa)
end

-- Return true if there is a TC flag.
function Query:have_tc()
    return ch.i2b(self._.have_tc)
end

-- Return true if there is a RD flag.
function Query:have_rd()
    return ch.i2b(self._.have_rd)
end

-- Return true if there is a RA flag.
function Query:have_ra()
    return ch.i2b(self._.have_ra)
end

-- Return true if there is a Z flag.
function Query:have_z()
    return ch.i2b(self._.have_z)
end

-- Return true if there is a AD flag.
function Query:have_ad()
    return ch.i2b(self._.have_ad)
end

-- Return true if there is a CD flag.
function Query:have_cd()
    return ch.i2b(self._.have_cd)
end

-- Return true if there is a RCODE.
function Query:have_rcode()
    return ch.i2b(self._.have_rcode)
end

-- Return true if there is an QDCOUNT.
function Query:have_qdcount()
    return ch.i2b(self._.have_qdcount)
end

-- Return true if there is an ANCOUNT.
function Query:have_ancount()
    return ch.i2b(self._.have_ancount)
end

-- Return true if there is a NSCOUNT.
function Query:have_nscount()
    return ch.i2b(self._.have_nscount)
end

-- Return true if there is an ARCOUNT.
function Query:have_arcount()
    return ch.i2b(self._.have_arcount)
end

-- Return the DNS ID.
function Query:id()
    return self._.id
end

-- Return the QR flag.
function Query:qr()
    return self._.qr
end

-- Return the OPCODE.
function Query:opcode()
    return self._.opcode
end

-- Return the AA flag.
function Query:aa()
    return self._.aa
end

-- Return the TC flag.
function Query:tc()
    return self._.tc
end

-- Return the RD flag.
function Query:rd()
    return self._.rd
end

-- Return the RA flag.
function Query:ra()
    return self._.ra
end

-- Return the Z flag.
function Query:z()
    return self._.z
end

-- Return the AD flag.
function Query:ad()
    return self._.ad
end

-- Return the CD flag.
function Query:cd()
    return self._.cd
end

-- Return the RCODE.
function Query:rcode()
    return self._.rcode
end

-- Return the QDCOUNT.
function Query:qdcount()
    return self._.qdcount
end

-- Return the ANCOUNT.
function Query:ancount()
    return self._.ancount
end

-- Return the NSCOUNT.
function Query:nscount()
    return self._.nscount
end

-- Return the ARCOUNT.
function Query:arcount()
    return self._.arcount
end

-- Return the actual number of questions found.
function Query:questions()
    return self._.questions
end

-- Return the actual number of answers found.
function Query:answers()
    return self._.answers
end

-- Return the actual number of authorities found.
function Query:authorities()
    return self._.authorities
end

-- Return the actual number of additionals found.
function Query:additionals()
    return self._.additionals
end

-- Start walking the resource record(s) (RR) found or continue with the next,
-- returns integer > 0 on error or end of RRs.
function Query:rr_next()
    return C.query_rr_next(self._)
end

-- Check if the RR at the current position was parsed successfully or not,
-- return 1 if successful.
function Query:rr_ok()
    return C.query_rr_ok(self._)
end

-- Return the FQDN of the current RR or an empty string on error.
function Query:rr_label()
    local ptr = C.query_rr_label(self._)
    if ptr == nil then
        return ""
    end
    return ffi.string(ptr)
end

-- Return an integer with the RR type.
function Query:rr_type()
    return C.query_rr_type(self._)
end

-- Return an integer with the RR class.
function Query:rr_class()
    return C.query_rr_class(self._)
end

-- Return an integer with the RR TTL.
function Query:rr_ttl()
    return C.query_rr_ttl(self._)
end

-- dnsjit.core.tracking (3)
return Query

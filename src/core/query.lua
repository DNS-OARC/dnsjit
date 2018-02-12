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
--   print(q:src(), q:dst(), q.id, q.rcode)
--
-- The core object that is passed between receiver and receivee and describes
-- a DNS message, how it was captured or generated.
-- .SS Attributes
-- .TP
-- sid
-- Source ID, used to track the unique source of the query.
-- See also
-- .BR dnsjit.core.tracking (3).
-- .TP
-- qid
-- Query ID, used to track the unique query from a source.
-- See also
-- .BR dnsjit.core.tracking (3).
-- .TP
-- sport
-- Source port.
-- .TP
-- dport
-- Destination port.
-- .TP
-- have_id
-- Set if there is a DNS ID.
-- .TP
-- have_qr
-- Set if there is a QR flag.
-- .TP
-- have_opcode
-- Set if there is an OPCODE.
-- .TP
-- have_aa
-- Set if there is a AA flag.
-- .TP
-- have_tc
-- Set if there is a TC flag.
-- .TP
-- have_rd
-- Set if there is a RD flag.
-- .TP
-- have_ra
-- Set if there is a RA flag.
-- .TP
-- have_z
-- Set if there is a Z flag.
-- .TP
-- have_ad
-- Set if there is a AD flag.
-- .TP
-- have_cd
-- Set if there is a CD flag.
-- .TP
-- have_rcode
-- Set if there is a RCODE.
-- .TP
-- have_qdcount
-- Set if there is an QDCOUNT.
-- .TP
-- have_ancount
-- Set if there is an ANCOUNT.
-- .TP
-- have_nscount
-- Set if there is a NSCOUNT.
-- .TP
-- have_arcount
-- Set if there is an ARCOUNT.
-- .TP
-- id
-- The DNS ID.
-- .TP
-- qr
-- The QR flag.
-- .TP
-- opcode
-- The OPCODE.
-- .TP
-- aa
-- The AA flag.
-- .TP
-- tc
-- The TC flag.
-- .TP
-- rd
-- The RD flag.
-- .TP
-- ra
-- The RA flag.
-- .TP
-- z
-- The Z flag.
-- .TP
-- ad
-- The AD flag.
-- .TP
-- cd
-- The CD flag.
-- .TP
-- rcode
-- The RCODE.
-- .TP
-- qdcount
-- The QDCOUNT.
-- .TP
-- ancount
-- The ANCOUNT.
-- .TP
-- nscount
-- The NSCOUNT.
-- .TP
-- arcount
-- The ARCOUNT.
-- .TP
-- questions
-- The actual number of questions found.
-- .TP
-- answers
-- The actual number of answers found.
-- .TP
-- authorities
-- The actual number of authorities found.
-- .TP
-- additionals
-- The actual number of additionals found.
module(...,package.seeall)

local ch = require("dnsjit.core.chelpers")
require("dnsjit.core.query_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_query_t"
local core_query_t
local Query = {}

-- Create a new query or bind an existing
-- .IR core_query_t .
function Query.new(self)
    if not ffi.istype(t_name, self) then
        self = C.core_query_new()
    end
    ffi.gc(self, C.core_query_free)
    return self
end

-- Return the Log object to control logging of this instance or module.
function Query:log()
    if self == nil then
        return C.core_query_log()
    end
    return self._log
end

-- Parse the DNS headers or the query.
function Query:parse_header()
    return ch.z2n(C.core_query_parse_header(self))
end

-- Parse the full DNS message or just the body if the header was already parsed.
function Query:parse()
    return ch.z2n(C.core_query_parse(self))
end

-- Return the IP source as a string.
function Query:src()
    return ffi.string(C.core_query_src(self))
end

-- Return the IP destination as a string.
function Query:dst()
    return ffi.string(C.core_query_dst(self))
end

-- Start walking the resource record(s) (RR) found or continue with the next,
-- returns integer > 0 on error or end of RRs.
function Query:rr_next()
    return C.core_query_rr_next(self)
end

-- Check if the RR at the current position was parsed successfully or not,
-- return 1 if successful.
function Query:rr_ok()
    return C.core_query_rr_ok(self)
end

-- Return the FQDN of the current RR or an empty string on error.
function Query:rr_label()
    local ptr = C.core_query_rr_label(self)
    if ptr == nil then
        return ""
    end
    return ffi.string(ptr)
end

-- Return an integer with the RR type.
function Query:rr_type()
    return C.core_query_rr_type(self)
end

-- Return an integer with the RR class.
function Query:rr_class()
    return C.core_query_rr_class(self)
end

-- Return an integer with the RR TTL.
function Query:rr_ttl()
    return C.core_query_rr_ttl(self)
end

core_query_t = ffi.metatype(t_name, { __index = Query })

-- dnsjit.core.tracking (3)
return Query

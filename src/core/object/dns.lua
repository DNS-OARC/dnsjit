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

-- dnsjit.core.object.dns
-- Container of a DNS message
--   local query = require("dnsjit.core.object.dns")
--   local q = query.new(pkt)
--   print(q:src(), q:dst(), q.id, q.rcode)
--
-- The object that describes a DNS message.
-- .SS Attributes
-- .TP
-- src_id
-- Source ID, used to track the query through the input, filter and output
-- modules.
-- See also
-- .BR dnsjit.core.tracking (3).
-- .TP
-- qr_id
-- Query/Response ID, used to track the query through the input, filter
-- and output modules.
-- See also
-- .BR dnsjit.core.tracking (3).
-- .TP
-- dst_id
-- Destination ID, used to track the query through the input, filter
-- and output modules.
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

require("dnsjit.core.object.dns_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_dns_t"
local core_object_dns_t
local Dns = {}

-- Create a new DNS object ontop of a packet.
function Dns.new(packet)
    if not ffi.istype("core_object_packet_t*", packet) then
        return
    end
    local self = C.core_object_dns_new(packet)
    ffi.gc(self, C.core_object_dns_free)
    return self
end

-- Return the textual type of the object.
function Dns:type()
    return "dns"
end

-- Return the previous object.
function Dns:prev()
    return self.obj_prev
end

-- Return the Log object to control logging of this instance or module.
function Dns:log()
    return C.core_object_dns_log()
end

-- Parse the DNS headers or the query, returns 0 on success.
function Dns:parse_header()
    return C.core_object_dns_parse_header(self)
end

-- Parse the full DNS message or just the body if the header was already
-- parsed, returns 0 on success.
function Dns:parse()
    return C.core_object_dns_parse(self)
end

-- Return the IP source as a string.
function Dns:src()
    return ffi.string(C.core_object_dns_src(self))
end

-- Return the IP destination as a string.
function Dns:dst()
    return ffi.string(C.core_object_dns_dst(self))
end

-- Start walking the resource record(s) (RR) found or continue with the next.
-- Returns 0 on success, < 0 on end of RRs and > 0 on error.
function Dns:rr_next()
    return C.core_object_dns_rr_next(self)
end

-- Check if the RR at the current position was parsed successfully or not,
-- returns 1 if successful.
function Dns:rr_ok()
    return C.core_object_dns_rr_ok(self)
end

-- Return the FQDN of the current RR or nil on error.
function Dns:rr_label()
    local ptr = C.core_object_dns_rr_label(self)
    if ptr == nil then
        return nil
    end
    return ffi.string(ptr)
end

-- Return an integer with the RR type.
function Dns:rr_type()
    return C.core_object_dns_rr_type(self)
end

-- Return an integer with the RR class.
function Dns:rr_class()
    return C.core_object_dns_rr_class(self)
end

-- Return an integer with the RR TTL.
function Dns:rr_ttl()
    return C.core_object_dns_rr_ttl(self)
end

core_object_dns_t = ffi.metatype(t_name, { __index = Dns })

-- dnsjit.core.object (3),
-- dnsjit.core.tracking (3)
return Dns

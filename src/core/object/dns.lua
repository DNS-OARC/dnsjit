-- Copyright (c) 2018-2025 OARC, Inc.
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
-- .SS Parse DNS header and check if query or response
--   local dns = require("dnsjit.core.object.dns").new(payload)
--   if dns:parse_header() == 0 then
--     if dns.qr == 0 then
--       print(dns.id, dns.opcode_tostring(dns.opcode))
--     else
--       print(dns.id, dns.rcode_tostring(dns.rcode))
--     end
--   end
-- .SS Print a DNS payload
--   local dns = require("dnsjit.core.object.dns").new(payload)
--   dns:print()
-- .SS Parse a DNS payload
--   local dns = require("dnsjit.core.object.dns").new(payload)
--   local qs, q_labels, rrs, rr_labels = dns:parse()
--   if qs and q_labels then
--     ...
--     if rrs and rr_labels then
--       ...
--     end
--   end
--
-- The object that describes a DNS message.
-- .SS Attributes
-- .TP
-- includes_dnslen
-- If non-zero then this indicates that the DNS length is included in the
-- payload (for example if the transport is TCP) and will affect parsing of it.
-- .TP
-- have_dnslen
-- Set if the dnslen was included in the payload and could be read.
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
-- dnslen
-- The DNS length found in the payload.
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
-- .SS Constants
-- The following tables exists for DNS parameters, taken from
-- .I https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
-- on the 2016-12-09.
-- .LP
-- .IR CLASS ,
-- .IR CLASS_STR ,
-- .IR TYPE ,
-- .IR TYPE_STR ,
-- .IR OPCODE ,
-- .IR OPCODE_STR ,
-- .IR RCODE ,
-- .IR RCODE_STR ,
-- .IR AFSDB ,
-- .IR AFSDB_STR ,
-- .IR DHCID ,
-- .IR DHCID_STR ,
-- .IR ENDS0 ,
-- .IR ENDS0_STR
-- .LP
-- The
-- .I *_STR
-- tables can be used to get a textual representation of the numbers, see also
-- .IR class_tostring() ,
-- .IR type_tostring() ,
-- .IR opcode_tostring() ,
-- .IR rcode_tostring() ,
-- .IR afsdb_tostring() ,
-- .I dhcid_tostring()
-- and
-- .IR edns0_tostring() .
module(...,package.seeall)

require("dnsjit.core.object.dns_h")
local label = require("dnsjit.core.object.dns.label")
local Q = require("dnsjit.core.object.dns.q")
local RR = require("dnsjit.core.object.dns.rr")
local ffi = require("ffi")
local C = ffi.C

local t_name = "core_object_dns_t"
local core_object_dns_t
local Dns = {
    CLASS = {
        IN = 1,
        CH = 3,
        HS = 4,
        NONE = 254,
        ANY = 255,
    },
    TYPE = {
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        RP = 17,
        AFSDB = 18,
        X25 = 19,
        ISDN = 20,
        RT = 21,
        NSAP = 22,
        NSAP_PTR = 23,
        SIG = 24,
        KEY = 25,
        PX = 26,
        GPOS = 27,
        AAAA = 28,
        LOC = 29,
        NXT = 30,
        EID = 31,
        NIMLOC = 32,
        SRV = 33,
        ATMA = 34,
        NAPTR = 35,
        KX = 36,
        CERT = 37,
        A6 = 38,
        DNAME = 39,
        SINK = 40,
        OPT = 41,
        APL = 42,
        DS = 43,
        SSHFP = 44,
        IPSECKEY = 45,
        RRSIG = 46,
        NSEC = 47,
        DNSKEY = 48,
        DHCID = 49,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        TLSA = 52,
        SMIMEA = 53,
        HIP = 55,
        NINFO = 56,
        RKEY = 57,
        TALINK = 58,
        CDS = 59,
        CDNSKEY = 60,
        OPENPGPKEY = 61,
        CSYNC = 62,
        SPF = 99,
        UINFO = 100,
        UID = 101,
        GID = 102,
        UNSPEC = 103,
        NID = 104,
        L32 = 105,
        L64 = 106,
        LP = 107,
        EUI48 = 108,
        EUI64 = 109,
        TKEY = 249,
        TSIG = 250,
        IXFR = 251,
        AXFR = 252,
        MAILB = 253,
        MAILA = 254,
        ANY = 255,
        URI = 256,
        CAA = 257,
        AVC = 258,
        TA = 32768,
        DLV = 32769,
    },
    OPCODE = {
        QUERY = 0,
        IQUERY = 1,
        STATUS = 2,
        NOTIFY = 4,
        UPDATE = 5,
    },
    RCODE = {
        NOERROR = 0,
        FORMERR = 1,
        SERVFAIL = 2,
        NXDOMAIN = 3,
        NOTIMP = 4,
        REFUSED = 5,
        YXDOMAIN = 6,
        YXRRSET = 7,
        NXRRSET = 8,
        NOTAUTH = 9,
        NOTZONE = 10,
        BADVERS = 16,
        BADSIG = 16,
        BADKEY = 17,
        BADTIME = 18,
        BADMODE = 19,
        BADNAME = 20,
        BADALG = 21,
        BADTRUNC = 22,
        BADCOOKIE = 23,
    },
    AFSDB = {
        SUBTYPE_AFS3LOCSRV = 1,
        SUBTYPE_DCENCA_ROOT = 2,
    },
    DHCID = {
        TYPE_1OCTET = 0,
        TYPE_DATAOCTET = 1,
        TYPE_CLIENT_DUID = 2,
    },
    EDNS0 = {
        OPT_LLQ = 1,
        OPT_UL = 2,
        OPT_NSID = 3,
        OPT_DAU = 5,
        OPT_DHU = 6,
        OPT_N3U = 7,
        OPT_CLIENT_SUBNET = 8,
        OPT_EXPIRE = 9,
        OPT_COOKIE = 10,
        OPT_TCP_KEEPALIVE = 11,
        OPT_PADDING = 12,
        OPT_CHAIN = 13,
        OPT_DEVICEID = 26946,
    },
}
local _CLASS = {}
_CLASS[Dns.CLASS.IN] = "IN"
_CLASS[Dns.CLASS.CH] = "CH"
_CLASS[Dns.CLASS.HS] = "HS"
_CLASS[Dns.CLASS.NONE] = "NONE"
_CLASS[Dns.CLASS.ANY] = "ANY"
local _TYPE = {}
_TYPE[Dns.TYPE.A] = "A"
_TYPE[Dns.TYPE.NS] = "NS"
_TYPE[Dns.TYPE.MD] = "MD"
_TYPE[Dns.TYPE.MF] = "MF"
_TYPE[Dns.TYPE.CNAME] = "CNAME"
_TYPE[Dns.TYPE.SOA] = "SOA"
_TYPE[Dns.TYPE.MB] = "MB"
_TYPE[Dns.TYPE.MG] = "MG"
_TYPE[Dns.TYPE.MR] = "MR"
_TYPE[Dns.TYPE.NULL] = "NULL"
_TYPE[Dns.TYPE.WKS] = "WKS"
_TYPE[Dns.TYPE.PTR] = "PTR"
_TYPE[Dns.TYPE.HINFO] = "HINFO"
_TYPE[Dns.TYPE.MINFO] = "MINFO"
_TYPE[Dns.TYPE.MX] = "MX"
_TYPE[Dns.TYPE.TXT] = "TXT"
_TYPE[Dns.TYPE.RP] = "RP"
_TYPE[Dns.TYPE.AFSDB] = "AFSDB"
_TYPE[Dns.TYPE.X25] = "X25"
_TYPE[Dns.TYPE.ISDN] = "ISDN"
_TYPE[Dns.TYPE.RT] = "RT"
_TYPE[Dns.TYPE.NSAP] = "NSAP"
_TYPE[Dns.TYPE.NSAP_PTR] = "NSAP_PTR"
_TYPE[Dns.TYPE.SIG] = "SIG"
_TYPE[Dns.TYPE.KEY] = "KEY"
_TYPE[Dns.TYPE.PX] = "PX"
_TYPE[Dns.TYPE.GPOS] = "GPOS"
_TYPE[Dns.TYPE.AAAA] = "AAAA"
_TYPE[Dns.TYPE.LOC] = "LOC"
_TYPE[Dns.TYPE.NXT] = "NXT"
_TYPE[Dns.TYPE.EID] = "EID"
_TYPE[Dns.TYPE.NIMLOC] = "NIMLOC"
_TYPE[Dns.TYPE.SRV] = "SRV"
_TYPE[Dns.TYPE.ATMA] = "ATMA"
_TYPE[Dns.TYPE.NAPTR] = "NAPTR"
_TYPE[Dns.TYPE.KX] = "KX"
_TYPE[Dns.TYPE.CERT] = "CERT"
_TYPE[Dns.TYPE.A6] = "A6"
_TYPE[Dns.TYPE.DNAME] = "DNAME"
_TYPE[Dns.TYPE.SINK] = "SINK"
_TYPE[Dns.TYPE.OPT] = "OPT"
_TYPE[Dns.TYPE.APL] = "APL"
_TYPE[Dns.TYPE.DS] = "DS"
_TYPE[Dns.TYPE.SSHFP] = "SSHFP"
_TYPE[Dns.TYPE.IPSECKEY] = "IPSECKEY"
_TYPE[Dns.TYPE.RRSIG] = "RRSIG"
_TYPE[Dns.TYPE.NSEC] = "NSEC"
_TYPE[Dns.TYPE.DNSKEY] = "DNSKEY"
_TYPE[Dns.TYPE.DHCID] = "DHCID"
_TYPE[Dns.TYPE.NSEC3] = "NSEC3"
_TYPE[Dns.TYPE.NSEC3PARAM] = "NSEC3PARAM"
_TYPE[Dns.TYPE.TLSA] = "TLSA"
_TYPE[Dns.TYPE.SMIMEA] = "SMIMEA"
_TYPE[Dns.TYPE.HIP] = "HIP"
_TYPE[Dns.TYPE.NINFO] = "NINFO"
_TYPE[Dns.TYPE.RKEY] = "RKEY"
_TYPE[Dns.TYPE.TALINK] = "TALINK"
_TYPE[Dns.TYPE.CDS] = "CDS"
_TYPE[Dns.TYPE.CDNSKEY] = "CDNSKEY"
_TYPE[Dns.TYPE.OPENPGPKEY] = "OPENPGPKEY"
_TYPE[Dns.TYPE.CSYNC] = "CSYNC"
_TYPE[Dns.TYPE.SPF] = "SPF"
_TYPE[Dns.TYPE.UINFO] = "UINFO"
_TYPE[Dns.TYPE.UID] = "UID"
_TYPE[Dns.TYPE.GID] = "GID"
_TYPE[Dns.TYPE.UNSPEC] = "UNSPEC"
_TYPE[Dns.TYPE.NID] = "NID"
_TYPE[Dns.TYPE.L32] = "L32"
_TYPE[Dns.TYPE.L64] = "L64"
_TYPE[Dns.TYPE.LP] = "LP"
_TYPE[Dns.TYPE.EUI48] = "EUI48"
_TYPE[Dns.TYPE.EUI64] = "EUI64"
_TYPE[Dns.TYPE.TKEY] = "TKEY"
_TYPE[Dns.TYPE.TSIG] = "TSIG"
_TYPE[Dns.TYPE.IXFR] = "IXFR"
_TYPE[Dns.TYPE.AXFR] = "AXFR"
_TYPE[Dns.TYPE.MAILB] = "MAILB"
_TYPE[Dns.TYPE.MAILA] = "MAILA"
_TYPE[Dns.TYPE.ANY] = "ANY"
_TYPE[Dns.TYPE.URI] = "URI"
_TYPE[Dns.TYPE.CAA] = "CAA"
_TYPE[Dns.TYPE.AVC] = "AVC"
_TYPE[Dns.TYPE.TA] = "TA"
_TYPE[Dns.TYPE.DLV] = "DLV"
local _OPCODE = {}
_OPCODE[Dns.OPCODE.QUERY] = "QUERY"
_OPCODE[Dns.OPCODE.IQUERY] = "IQUERY"
_OPCODE[Dns.OPCODE.STATUS] = "STATUS"
_OPCODE[Dns.OPCODE.NOTIFY] = "NOTIFY"
_OPCODE[Dns.OPCODE.UPDATE] = "UPDATE"
local _RCODE = {}
_RCODE[Dns.RCODE.NOERROR] = "NOERROR"
_RCODE[Dns.RCODE.FORMERR] = "FORMERR"
_RCODE[Dns.RCODE.SERVFAIL] = "SERVFAIL"
_RCODE[Dns.RCODE.NXDOMAIN] = "NXDOMAIN"
_RCODE[Dns.RCODE.NOTIMP] = "NOTIMP"
_RCODE[Dns.RCODE.REFUSED] = "REFUSED"
_RCODE[Dns.RCODE.YXDOMAIN] = "YXDOMAIN"
_RCODE[Dns.RCODE.YXRRSET] = "YXRRSET"
_RCODE[Dns.RCODE.NXRRSET] = "NXRRSET"
_RCODE[Dns.RCODE.NOTAUTH] = "NOTAUTH"
_RCODE[Dns.RCODE.NOTZONE] = "NOTZONE"
_RCODE[Dns.RCODE.BADVERS] = "BADVERS"
_RCODE[Dns.RCODE.BADSIG] = "BADSIG"
_RCODE[Dns.RCODE.BADKEY] = "BADKEY"
_RCODE[Dns.RCODE.BADTIME] = "BADTIME"
_RCODE[Dns.RCODE.BADMODE] = "BADMODE"
_RCODE[Dns.RCODE.BADNAME] = "BADNAME"
_RCODE[Dns.RCODE.BADALG] = "BADALG"
_RCODE[Dns.RCODE.BADTRUNC] = "BADTRUNC"
_RCODE[Dns.RCODE.BADCOOKIE] = "BADCOOKIE"
local _AFSDB = {}
_AFSDB[Dns.AFSDB.SUBTYPE_AFS3LOCSRV] = "SUBTYPE_AFS3LOCSRV"
_AFSDB[Dns.AFSDB.SUBTYPE_DCENCA_ROOT] = "SUBTYPE_DCENCA_ROOT"
local _DHCID = {}
_DHCID[Dns.DHCID.TYPE_1OCTET] = "TYPE_1OCTET"
_DHCID[Dns.DHCID.TYPE_DATAOCTET] = "TYPE_DATAOCTET"
_DHCID[Dns.DHCID.TYPE_CLIENT_DUID] = "TYPE_CLIENT_DUID"
local _EDNS0 = {}
_EDNS0[Dns.EDNS0.OPT_LLQ] = "OPT_LLQ"
_EDNS0[Dns.EDNS0.OPT_UL] = "OPT_UL"
_EDNS0[Dns.EDNS0.OPT_NSID] = "OPT_NSID"
_EDNS0[Dns.EDNS0.OPT_DAU] = "OPT_DAU"
_EDNS0[Dns.EDNS0.OPT_DHU] = "OPT_DHU"
_EDNS0[Dns.EDNS0.OPT_N3U] = "OPT_N3U"
_EDNS0[Dns.EDNS0.OPT_CLIENT_SUBNET] = "OPT_CLIENT_SUBNET"
_EDNS0[Dns.EDNS0.OPT_EXPIRE] = "OPT_EXPIRE"
_EDNS0[Dns.EDNS0.OPT_COOKIE] = "OPT_COOKIE"
_EDNS0[Dns.EDNS0.OPT_TCP_KEEPALIVE] = "OPT_TCP_KEEPALIVE"
_EDNS0[Dns.EDNS0.OPT_PADDING] = "OPT_PADDING"
_EDNS0[Dns.EDNS0.OPT_CHAIN] = "OPT_CHAIN"
_EDNS0[Dns.EDNS0.OPT_DEVICEID] = "OPT_DEVICEID"
Dns.CLASS_STR = _CLASS
Dns.TYPE_STR = _TYPE
Dns.OPCODE_STR = _OPCODE
Dns.RCODE_STR = _RCODE
Dns.AFSDB_STR = _AFSDB
Dns.DHCID_STR = _DHCID
Dns.EDNS0_STR = _EDNS0

-- Create a new DNS object, optionally on-top of another object.
function Dns.new(obj)
    local self = C.core_object_dns_new()
    self.obj_prev = obj
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

-- Cast the object to the underlining object module and return it.
function Dns:cast()
    return self
end

-- Cast the object to the generic object module and return it.
function Dns:uncast()
    return ffi.cast("core_object_t*", self)
end

-- Make a copy of the object and return it.
function Dns:copy()
    return C.core_object_dns_copy(self)
end

-- Free the object, should only be used on copies or otherwise allocated.
function Dns:free()
    C.core_object_dns_free(self)
end

-- Reset the object readying it for reuse.
function Dns:reset()
    C.core_object_dns_reset(self)
end

-- Return the Log object to control logging of this module.
function Dns:log()
    return C.core_object_dns_log()
end

-- Begin parsing the underlaying object, first the header is parsed then
-- optionally continue calling
-- .IR parse_q ()
-- for the number of questions (see
-- .IR qdcount ).
-- After that continue calling
-- .IR parse_rr ()
-- for the number of answers, authorities and additionals resource records
-- (see
-- .IR ancount ", "
-- .I nscount
-- and
-- .IR arcount ).
-- Returns 0 on success or negative integer on error which can be for
-- malformed or truncated DNS (-2) or if more space for labels is needed (-3).
function Dns:parse_header()
    return C.core_object_dns_parse_header(self)
end

-- Parse the next resource record as a question.
-- Returns 0 on success or negative integer on error which can be for
-- malformed or truncated DNS (-2) or if more space for labels is needed (-3).
function Dns:parse_q(q, labels, num_labels)
    return C.core_object_dns_parse_q(self, q, labels, num_labels)
end

-- Parse the next resource record.
-- Returns 0 on success or negative integer on error which can be for
-- malformed or truncated DNS (-2) or if more space for labels is needed (-3).
function Dns:parse_rr(rr, labels, num_labels)
    return C.core_object_dns_parse_rr(self, rr, labels, num_labels)
end

-- Begin parsing the underlaying object using
-- .IR parse_header "(), "
-- .IR parse_q ()
-- and
-- .IR parse_rr ().
-- The optional
-- .I num_labels
-- can be used to set a specific number of labels used for each question
-- and resource record (default 16).
-- Returns result code, an array of questions, an array of question labels,
-- an array of resource records and an array of resource records labels.
-- Result code is 0 on success or negative integer on error which can be for
-- malformed or truncated DNS (-2) or if more space for labels is needed (-3).
function Dns:parse(num_labels)
    local qs, qls, rrs, rrls = {}, {}, {}, {}
    if num_labels == nil then
        num_labels = 16
    end

    ret = self:parse_header()
    if ret ~= 0 then
        return ret, qs, qls, rrs, rrls
    end
    for n = 1, self.qdcount do
        local labels = label.new(num_labels)
        local q = Q.new()
        local ret = C.core_object_dns_parse_q(self, q, labels, num_labels)

        if ret ~= 0 then
            return ret, qs, qls, rrs, rrls
        end
        table.insert(qs, q)
        table.insert(qls, labels)
    end
    for n = 1, self.ancount do
        local labels = label.new(num_labels)
        local rr = RR.new()
        local ret = C.core_object_dns_parse_rr(self, rr, labels, num_labels)

        if ret ~= 0 then
            return ret, qs, qls, rrs, rrls
        end
        table.insert(rrs, rr)
        table.insert(rrls, labels)
    end
    for n = 1, self.nscount do
        local labels = label.new(num_labels)
        local rr = RR.new()
        local ret = C.core_object_dns_parse_rr(self, rr, labels, num_labels)

        if ret ~= 0 then
            return ret, qs, qls, rrs, rrls
        end
        table.insert(rrs, rr)
        table.insert(rrls, labels)
    end
    for n = 1, self.arcount do
        local labels = label.new(num_labels)
        local rr = RR.new()
        local ret = C.core_object_dns_parse_rr(self, rr, labels, num_labels)

        if ret ~= 0 then
            return ret, qs, qls, rrs, rrls
        end
        table.insert(rrs, rr)
        table.insert(rrls, labels)
    end

    return 0, qs, qls, rrs, rrls
end

-- Begin parsing the underlaying object using
-- .IR parse_header "(), "
-- .IR parse_q ()
-- and
-- .IR parse_rr (),
-- and print it's content.
-- The optional
-- .I num_labels
-- can be used to set a specific number of labels used for each question
-- and resource record (default 16).
function Dns:print(num_labels)
    if num_labels == nil then
        num_labels = 16
    end
    local labels = label.new(num_labels)
    local q = Q.new()
    local rr = RR.new()

    if self:parse_header() ~= 0 then
        return
    end

    local flags = {}
    if self.have_aa and self.aa == 1 then
        table.insert(flags, "AA")
    end
    if self.have_tc and self.tc == 1 then
        table.insert(flags, "TC")
    end
    if self.have_rd and self.rd == 1 then
        table.insert(flags, "RD")
    end
    if self.have_ra and self.ra == 1 then
        table.insert(flags, "RA")
    end
    if self.have_z and self.z == 1 then
        table.insert(flags, "Z")
    end
    if self.have_ad and self.ad == 1 then
        table.insert(flags, "AD")
    end
    if self.have_cd and self.cd == 1 then
        table.insert(flags, "CD")
    end

    print("id:", self.id)
    print("", "qr:", self.qr)
    print("", "opcode:", Dns.opcode_tostring(self.opcode))
    print("", "flags:", table.concat(flags, " "))
    print("", "rcode:", Dns.rcode_tostring(self.rcode))
    print("", "qdcount:", self.qdcount)
    print("", "ancount:", self.ancount)
    print("", "nscount:", self.nscount)
    print("", "arcount:", self.arcount)

    if self.qdcount > 0 then
        print("questions:", "class", "type", "labels")
        for n = 1, self.qdcount do
            if C.core_object_dns_parse_q(self, q, labels, num_labels) ~= 0 then
                return
            end
            print("", Dns.class_tostring(q.class), Dns.type_tostring(q.type), label.tooffstr(self, labels, num_labels))
        end
    end
    if self.ancount > 0 then
        print("answers:", "class", "type", "ttl", "labels", "RR labels")
        for n = 1, self.ancount do
            if C.core_object_dns_parse_rr(self, rr, labels, num_labels) ~= 0 then
                return
            end
            if rr.rdata_labels == 0 then
                print("", Dns.class_tostring(rr.class), Dns.type_tostring(rr.type), rr.ttl, label.tooffstr(self, labels, rr.labels))
            else
                print("", Dns.class_tostring(rr.class), Dns.type_tostring(rr.type), rr.ttl, label.tooffstr(self, labels, rr.labels), label.tooffstr(self, labels, rr.rdata_labels, rr.labels))
            end
        end
    end
    if self.nscount > 0 then
        print("authorities:", "class", "type", "ttl", "labels", "RR labels")
        for n = 1, self.nscount do
            if C.core_object_dns_parse_rr(self, rr, labels, num_labels) ~= 0 then
                return
            end
            if rr.rdata_labels == 0 then
                print("", Dns.class_tostring(rr.class), Dns.type_tostring(rr.type), rr.ttl, label.tooffstr(self, labels, rr.labels))
            else
                print("", Dns.class_tostring(rr.class), Dns.type_tostring(rr.type), rr.ttl, label.tooffstr(self, labels, rr.labels), label.tooffstr(self, labels, rr.rdata_labels, rr.labels))
            end
        end
    end
    if self.arcount > 0 then
        print("additionals:", "class", "type", "ttl", "labels", "RR labels")
        for n = 1, self.arcount do
            if C.core_object_dns_parse_rr(self, rr, labels, num_labels) ~= 0 then
                return
            end
            if rr.rdata_labels == 0 then
                print("", Dns.class_tostring(rr.class), Dns.type_tostring(rr.type), rr.ttl, label.tooffstr(self, labels, rr.labels))
            else
                print("", Dns.class_tostring(rr.class), Dns.type_tostring(rr.type), rr.ttl, label.tooffstr(self, labels, rr.labels), label.tooffstr(self, labels, rr.rdata_labels, rr.labels))
            end
        end
    end
end

-- Return the textual name for a class.
function Dns.class_tostring(class)
    if Dns.CLASS_STR[class] == nil then
        return "UNKNOWN("..class..")"
    end
    return Dns.CLASS_STR[class]
end

-- Return the textual name for a type.
function Dns.type_tostring(type)
    if Dns.TYPE_STR[type] == nil then
        return "UNKNOWN("..type..")"
    end
    return Dns.TYPE_STR[type]
end

-- Return the textual name for an opcode.
function Dns.opcode_tostring(opcode)
    if Dns.OPCODE_STR[opcode] == nil then
        return "UNKNOWN("..opcode..")"
    end
    return Dns.OPCODE_STR[opcode]
end

-- Return the textual name for a rcode.
function Dns.rcode_tostring(rcode)
    if Dns.RCODE_STR[rcode] == nil then
        return "UNKNOWN("..rcode..")"
    end
    return Dns.RCODE_STR[rcode]
end

-- Return the textual name for an afsdb subtype.
function Dns.afsdb_tostring(afsdb)
    if Dns.AFSDB_STR[afsdb] == nil then
        return "UNKNOWN("..afsdb..")"
    end
    return Dns.AFSDB_STR[afsdb]
end

-- Return the textual name for a dhcid type.
function Dns.dhcid_tostring(dhcid)
    if Dns.DHCID_STR[dhcid] == nil then
        return "UNKNOWN("..dhcid..")"
    end
    return Dns.DHCID_STR[dhcid]
end

-- Return the textual name for an EDNS0 OPT record.
function Dns.edns0_tostring(edns0)
    if Dns.EDNS0_STR[edns0] == nil then
        return "UNKNOWN("..edns0..")"
    end
    return Dns.EDNS0_STR[edns0]
end

core_object_dns_t = ffi.metatype(t_name, { __index = Dns })

-- dnsjit.core.object (3),
-- dnsjit.core.object.payload (3),
-- dnsjit.core.object.dns.label (3),
-- dnsjit.core.object.dns.q (3),
-- dnsjit.core.object.dns.rr (3)
return Dns

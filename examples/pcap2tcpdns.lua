#!/usr/bin/env dnsjit
-- Author: Petr Špaček (ISC)

-- Convert PCAP with IPv[46] & UDP payloads into TCP-stream binary format as
-- specified by RFC 1035 section "4.2.2. TCP usage". Each packet is preceded by
-- 2-byte pre‐ambule which specifies length of the following DNS message in
-- network byte order, immediately followed by raw bytes of the DNS message.
--
-- Outputs raw binary to stdout!
--
-- This script does not do any filtering or input sanitation.
-- For filtering capabilities look at dnscap -o dump_format=tcpdns

local bit = require("bit")
local ffi = require("ffi")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("pcap2tcpdns")
local getopt = require("dnsjit.lib.getopt").new({
	{ "r", "read", "-", "input file to read, use - for stdin", "?" },
})

local tmpbuf = ffi.new("uint8_t[?]", 2)
local function put_uint16_be(dst, offset, src)
	dst[offset] = bit.rshift(bit.band(src, 0xff00), 8)
	dst[offset + 1] = bit.band(src, 0xff)
end

log:enable("all")

-- Parse arguments
local args = {}
getopt:parse()
args.read = getopt:val("r")

-- Display help
if getopt:val("help") then
	getopt:usage()
	return
end

-- Set up input
if args.read ~= "" then
	log:notice("using input PCAP "..args.read)
	if input:open_offline(args.read) ~= 0 then
		log:fatal("failed to open input PCAP "..args.read)
	end
else
	getopt:usage()
	log:fatal("input must be specified, use -r")
end
layer:producer(input)
local produce, pctx = layer:produce()

-- set up output
io.stdout:setvbuf("full")

local obj, obj_udp, obj_pl
local npacketsout = 0
local npacketsskip = 0
local UDP_ID = object.UDP
while true do
	obj = produce(pctx)
	if obj == nil then break end

	obj_pl = obj:cast_to(object.PAYLOAD)
	if obj_pl ~= nil and obj_pl.len <= 65535 and obj_pl:prev().obj_type == UDP_ID then
		-- RFC 1035 framing has just the DNS message size as two bytes (big-endian).
		put_uint16_be(tmpbuf, 0, obj_pl.len)
		io.stdout:write(ffi.string(tmpbuf, 2))
		io.stdout:write(ffi.string(obj_pl.payload, obj_pl.len))
		npacketsout = npacketsout + 1
	else
		npacketsskip = npacketsskip + 1
	end
end
log:info(string.format("%d packets copied, %d skipped", npacketsout, npacketsskip))

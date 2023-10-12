#!/usr/bin/env dnsjit

-- Convert PCAP with IPv[46] & UDP payloads into TCP-stream binary format as
-- specified by RFC 1035 section "4.2.2. TCP usage". Each packet is preceded by
-- 2-byte pre‐ambule which specifies length of the following DNS packet in
-- network byte order, immediately followed by raw bytes of the packet.
--
-- This script does not do any filtering or input sanitation.
-- Outputs raw binary to stdout!

local bit = require("bit")
local ffi = require("ffi")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("extract-clients.lua")
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

local obj, obj_pcap_in, obj_ip, obj_udp, obj_pl
local npacketsin = 0
while true do
	obj = produce(pctx)
	if obj == nil then break end
	npacketsin = npacketsin + 1

	obj_ip = obj:cast_to(object.IP)
	if obj_ip == nil then
		obj_ip = obj:cast_to(object.IP6)
	end

	obj_udp = obj:cast_to(object.UDP)
	obj_pl = obj:cast_to(object.PAYLOAD)
	obj_pcap_in = obj:cast_to(object.PCAP)
	if obj_ip ~= nil and obj_udp ~= nil and obj_pl ~= nil and obj_pcap_in ~= nil then
		-- UDP header length is 8 bytes and is included in the ulen field below.
		-- RFC 1035 framing has just the DNS message size as two bytes (big-endian).
		put_uint16_be(tmpbuf, 0, obj_udp.ulen - 8)
		io.stdout:write(ffi.string(tmpbuf, 2))
		io.stdout:write(ffi.string(obj_pl.payload, obj_pl.len))
	end
end
log:info(string.format("processed %d packets", npacketsin))

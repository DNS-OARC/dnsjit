#!/usr/bin/env dnsjit
local bit = require("bit")
local ffi = require("ffi")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("pcap2tcpdns")
local getopt = require("dnsjit.lib.getopt").new({
    { "r", "read", "-", "input file to read, use - for stdin", "?" },
})

log:enable("all")

-- Parse arguments
local args = {}
getopt:parse()
args.read = getopt:val("r")

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
io.stdout:setvbuf("no")
io.stderr:setvbuf("no")

local obj, obj_pcap_in, obj_ip, obj_udp, obj_pl
local npacketsin = 0
while true do
    obj = produce(pctx)
    if obj == nil then break end
    npacketsin = npacketsin + 1
    print("\ntype", "length")

    obj_pcap_in = obj:cast_to(object.PCAP)
    print(obj_pcap_in:type(), tonumber(obj_pcap_in.len), "(len)")
    print(obj_pcap_in:type(), tonumber(obj_pcap_in.caplen), "(caplen)")

    obj_ip = obj:cast_to(object.IP)
    if obj_ip then
        print(obj_ip:type(), tonumber(obj_ip.len), "(len)")
    else
        obj_ip = obj:cast_to(object.IP6)
        print(obj_ip:type(), tonumber(obj_ip.plen), "(plen)")
    end

    obj_udp = obj:cast_to(object.UDP)
    if obj_udp then
        print(obj_udp:type(), tonumber(obj_udp.ulen))
    else
        obj_tcp = obj:cast_to(object.TCP)
        if obj_tcp then
            print(obj_tcp:type())
        end
    end

    obj_pl = obj:cast_to(object.PAYLOAD)
    print(obj_pl:type(), tonumber(obj_pl.len), "(len)")
    print(obj_pl:type(), tonumber(obj_pl.padding), "(padding)")
end
log:info(string.format("processed %d packets", npacketsin))

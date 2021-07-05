local zpcap = require("dnsjit.input.zpcap").new()

zpcap:lz4()
if zpcap:have_support() then
    print("lz4")
end
zpcap:zstd()
if zpcap:have_support() then
    print("zstd")
end

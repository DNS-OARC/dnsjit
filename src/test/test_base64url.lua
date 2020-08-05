base64url = require("dnsjit.lib.base64url")
ffi = require("ffi")

-- empty calls don't explode
base64url.encode()
base64url.decode()

-- empty string works
assert(base64url.decode(base64url.encode("")) == "")

-- regular string data
assert(base64url.encode("abcd") == "YWJjZA")
assert(base64url.decode(base64url.encode("abcd")) == "abcd")

-- invalid base64 data
base64url.decode("+")

-- check all symbols - arbitrary binary data
c_array = ffi.new("uint8_t[?]", 256)
bin_symbols = {}
for i = 0, 255 do
    bin_symbols[i + 1] = string.char(i)
    c_array[i] = i
end
bin_str = table.concat(bin_symbols)

assert(base64url.decode(base64url.encode(bin_str)) == bin_str)
assert(base64url.encode(c_array, 256) == base64url.encode(bin_str))

local duration = require("example.lib.duration")

require("dnsjit.lib.clock_h")
local C = require("ffi").C

local a = C.lib_clock_gettime("LIB_CLOCK_REALTIME")
a.sec = a.sec - 60000
local b = C.lib_clock_gettime("LIB_CLOCK_REALTIME")

print(duration.duration(a, b))

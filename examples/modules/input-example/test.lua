local ffi = require("ffi")
local zero = require("dnsjit.input.zero").new()

local producer, context = zero:produce()
local object = producer(context)

if ffi.istype("struct core_object*", object) then
    print("loading and usage successful")
end

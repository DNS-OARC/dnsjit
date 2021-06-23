local ffi = require("ffi")
local null = require("example.output.null").new()
require("dnsjit.core.object.null")

local receiver, context = null:receive()

local object = ffi.new("core_object_null_t")

receiver(context, object:uncast())

if null:packets() == 1 then
    print("loading and usage successful")
    os.exit(0)
end

os.exit(1)

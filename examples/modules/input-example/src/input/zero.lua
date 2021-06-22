-- example.input.zero
-- Generate empty objects (/dev/zero)
--   local input = require("example.input.zero").new()
--   input:receiver(filter_or_output)
--   input:run(1e6)
--
-- Input module for generating empty
-- .I core.object.null
-- objects, mostly used for testing.
module(...,package.seeall)

require("dnsjit.core.log")
require("dnsjit.core.receiver_h")
require("dnsjit.core.producer_h")

local loader = require("dnsjit.core.loader")
loader.load("example-input-zero/zero")

local ffi = require("ffi")
ffi.cdef[[
typedef struct input_zero {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;
} input_zero_t;

core_log_t* input_zero_log();

void input_zero_init(input_zero_t* self);
void input_zero_destroy(input_zero_t* self);
void input_zero_run(input_zero_t* self, uint64_t num);

core_producer_t input_zero_producer();
]]
local C = ffi.C

local t_name = "input_zero_t"
local input_zero_t = ffi.typeof(t_name)
local Zero = {}

-- Create a new Zero input.
function Zero.new()
    local self = {
        _receiver = nil,
        obj = input_zero_t(),
    }
    C.input_zero_init(self.obj)
    ffi.gc(self.obj, C.input_zero_destroy)
    return setmetatable(self, { __index = Zero })
end

-- Return the Log object to control logging of this instance or module.
function Zero:log()
    if self == nil then
        return C.input_zero_log()
    end
    return self.obj._log
end

-- Set the receiver to pass objects to.
function Zero:receiver(o)
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

-- Return the C functions and context for producing objects.
function Zero:produce()
    return C.input_zero_producer(), self.obj
end

-- Generate
-- .I num
-- empty objects and send them to the receiver.
function Zero:run(num)
    C.input_zero_run(self.obj, num)
end

return Zero

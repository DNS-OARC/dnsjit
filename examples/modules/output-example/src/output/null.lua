-- example.output.null
-- Output to nothing (/dev/null)
--   local output = require("example.output.null").new()
--
-- Output module for those that doesn't really like packets.
module(...,package.seeall)

require("dnsjit.core.log")
require("dnsjit.core.receiver_h")
require("dnsjit.core.producer_h")

local loader = require("dnsjit.core.loader")
loader.load("example-output-null/null")

local ffi = require("ffi")
ffi.cdef[[
typedef struct output_null {
    core_log_t      _log;
    core_producer_t prod;
    void*           ctx;
    size_t          pkts;
} output_null_t;

core_log_t* output_null_log();

void output_null_init(output_null_t* self);
void output_null_destroy(output_null_t* self);
void output_null_run(output_null_t* self, int64_t num);

core_receiver_t output_null_receiver();
]]
local C = ffi.C

local t_name = "output_null_t"
local output_null_t = ffi.typeof(t_name)
local Null = {}

-- Create a new Null output.
function Null.new()
    local self = {
        _producer = nil,
        obj = output_null_t(),
    }
    C.output_null_init(self.obj)
    ffi.gc(self.obj, C.output_null_destroy)
    return setmetatable(self, { __index = Null })
end

-- Return the Log object to control logging of this instance or module.
function Null:log()
    if self == nil then
        return C.output_null_log()
    end
    return self.obj._log
end

-- Return the C functions and context for receiving objects.
function Null:receive()
    return C.output_null_receiver(), self.obj
end

-- Set the producer to get objects from.
function Null:producer(o)
    self.obj.prod, self.obj.ctx = o:produce()
    self._producer = o
end

-- Retrieve all objects from the producer, if the optional
-- .I num
-- is a positive number then stop after that amount of objects have been
-- retrieved.
function Null:run(num)
    if num == nil then
        num = -1
    end
    C.output_null_run(self.obj, num)
end

-- Return the number of packets we sent into the void.
function Null:packets()
    return tonumber(self.obj.pkts)
end

return Null

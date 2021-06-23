-- example.filter.counter
-- Count objects passed through
--   local filter = require("example.filter.counter").new()
--   input:receiver(filter)
--   filter:receiver(output)
--   print(filter:count())
--
-- An example filter module that will count objects it sees.
module(...,package.seeall)

require("dnsjit.core.log")
require("dnsjit.core.receiver_h")
require("dnsjit.core.producer_h")

local loader = require("dnsjit.core.loader")
loader.load("example-filter-counter/counter")

local ffi = require("ffi")
ffi.cdef[[
typedef struct filter_counter {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;
    core_producer_t prod;
    void*           prod_ctx;

    size_t count;
} filter_counter_t;

core_log_t* filter_counter_log();

void filter_counter_init(filter_counter_t* self);
void filter_counter_destroy(filter_counter_t* self);

core_receiver_t filter_counter_receiver();
core_producer_t filter_counter_producer(filter_counter_t* self);
]]
local C = ffi.C

local t_name = "filter_counter_t"
local filter_counter_t = ffi.typeof(t_name)
local Counter = {}

-- Create a new Counter filter.
function Counter.new()
    local self = {
        _receiver = nil,
        _producer = nil,
        obj = filter_counter_t(),
    }
    C.filter_counter_init(self.obj)
    ffi.gc(self.obj, C.filter_counter_destroy)
    return setmetatable(self, { __index = Counter })
end

-- Return the Log object to control logging of this instance or module.
function Counter:log()
    if self == nil then
        return C.filter_counter_log()
    end
    return self.obj._log
end

-- Return the C functions and context for receiving objects.
function Counter:receive()
    return C.filter_counter_receiver(), self.obj
end

-- Set the receiver to pass objects to.
function Counter:receiver(o)
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

-- Return the C functions and context for producing objects.
function Counter:produce()
    return C.filter_counter_producer(self.obj), self.obj
end

-- Set the producer to get objects from.
function Counter:producer(o)
    self.obj.prod, self.obj.prod_ctx = o:produce()
    self._producer = o
end

-- Return counted objects.
function Counter:count()
    return tonumber(self.obj.count)
end

return Counter

local ffi = require("ffi")
local zero = require("example.input.zero").new()
local counter = require("example.filter.counter").new()
local null = require("example.output.null").new()

-- set the counter to receive objects created by zero
zero:receiver(counter)
-- set the null to receive objects passed through counter
counter:receiver(null)

-- run and create 10 objects
zero:run(10)

if counter:count() == 10 then
    print("loading and usage successful, counted "..counter:count().." objects")
    os.exit(0)
end

os.exit(1)

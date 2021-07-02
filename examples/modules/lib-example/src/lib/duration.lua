module(...,package.seeall)

require("dnsjit.core.timespec_h")
local ffi = require("ffi")

local Duration = {}

-- Return the duration between two core.timespec as a string.
function Duration.duration(a, b)
    if ffi.istype("core_timespec_t", a) ~= true then
        error("first argument is not a core_timespec_t")
    end
    if ffi.istype("core_timespec_t", b) ~= true then
        error("second argument is not a core_timespec_t")
    end
    if a.sec == b.sec then
        if a.nsec < b.nsec then
            return string.format("0.%09ds", tonumber(b.nsec-a.nsec))
        end
        return string.format("0.%09ds", tonumber(a.nsec-b.nsec))
    else
        local sec, nsec
        if a.sec < b.sec then
            sec = b.sec - a.sec
            nsec = 1e9 - a.nsec + b.nsec
        else
            sec = a.sec - b.sec
            nsec = 1e9 - b.nsec + a.nsec
        end
        if nsec >= 1e9 then
            sec = sec + ( nsec / 1e9 )
            nsec = nsec - 1e9
        end
        return string.format("%d.%09ds", tonumber(sec), tonumber(nsec))
    end
end

return Duration

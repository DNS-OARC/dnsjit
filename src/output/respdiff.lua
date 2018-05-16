-- Copyright (c) 2018, OARC, Inc.
-- All rights reserved.
--
-- This file is part of dnsjit.
--
-- dnsjit is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- dnsjit is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.

-- dnsjit.output.respdiff
-- Output to respdiff LMDB
--   local output = require("dnsjit.output.respdiff").new("/path/to/lmdb")
--
-- Output to an LMDB database that can be used by respdiff to compare the
-- responses found in the input data with the responses received. The receive
-- function expects to get a chain of 3
-- .IR core.object.payload ,
-- at the top in the chain is the query, after it the original response and
-- then the received response.
module(...,package.seeall)

require("dnsjit.output.respdiff_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_respdiff_t"
local output_respdiff_t = ffi.typeof(t_name)
local Respdiff = {}

-- Create a new Respdiff output.
function Respdiff.new(path)
    local self = {
        obj = output_respdiff_t(),
        path = path,
    }
    C.output_respdiff_init(self.obj, path)
    ffi.gc(self.obj, C.output_respdiff_destroy)
    return setmetatable(self, { __index = Respdiff })
end

-- Return the Log object to control logging of this instance or module.
function Respdiff:log()
    if self == nil then
        return C.output_respdiff_log()
    end
    return self.obj._log
end

-- Return the C functions and context for receiving objects.
function Respdiff:receive()
    return C.output_respdiff_receiver(), self.obj
end

-- Commit the LMDB transactions, can not store any more objects after this
-- call.
-- Returns 0 on success.
function Respdiff:commit()
    return C.output_respdiff_commit(self.obj)
end

-- Write out the JSON report that
-- .I respdiff
-- needs to continue processing.
-- The given
-- .I start_time
-- and
-- .I end_time
-- are used to fill the report.
function Respdiff:report(start_time, end_time)
    local report = io.open(self.path.."/report.json", "w+")
    report:write(string.format([[{
    "start_time": %d,
    "end_time": %d,
    "total_queries": %d,
    "total_answers": %d
}]], start_time, end_time, tonumber(self.obj.count), tonumber(self.obj.count)))
    report:close()
end

return Respdiff

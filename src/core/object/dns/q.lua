-- Copyright (c) 2018-2019, OARC, Inc.
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

-- dnsjit.core.object.dns.q
-- Container of a DNS question
--
-- The object that describes a DNS question.
-- .SS Attributes
-- .TP
-- have_type
-- Set if there is a type.
-- .TP
-- have_class
-- Set if there is a class.
-- .TP
-- type
-- The type.
-- .TP
-- class
-- The class.
-- .TP
-- labels
-- The number of labels found in the question.
module(...,package.seeall)

require("dnsjit.core.object.dns_h")
local ffi = require("ffi")

local Q = {}

-- Create a new question.
function Q.new(size)
    return ffi.new("core_object_dns_q_t")
end

-- dnsjit.core.object.dns (3)
return Q

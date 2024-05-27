-- Copyright (c) 2018-2024 OARC, Inc.
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

-- dnsjit.core.object.dns.rr
-- Container of a DNS resource record
--
-- The object that describes a DNS resource record.
-- .SS Attributes
-- .TP
-- have_type
-- Set if there is a type.
-- .TP
-- have_class
-- Set if there is a class.
-- .TP
-- have_ttl
-- Set if there is a ttl.
-- .TP
-- have_rdlength
-- Set if there is a rdlength.
-- .TP
-- have_rdata
-- Set if there is resource record data.
-- .TP
-- have_rdata_labels
-- Set if there are any labels within the rdata.
-- .TP
-- have_padding
-- Set if there is padding.
-- .TP
-- type
-- The type.
-- .TP
-- class
-- The class.
-- .TP
-- ttl
-- The TTL.
-- .TP
-- rdlength
-- The resource record data length.
-- .TP
-- labels
-- The number of labels found in the record.
-- .TP
-- rdata_offset
-- The offset within the payload for the resource record data.
-- .TP
-- rdata_labels
-- The number of labels found inside the resource record data.
-- .TP
-- padding_offset
-- The offset within the payload where the padding starts.
-- .TP
-- padding_length
-- The length of the padding.
module(...,package.seeall)

require("dnsjit.core.object.dns_h")
local ffi = require("ffi")

local Rr = {}

-- Create a new resource record.
function Rr.new()
    return ffi.new("core_object_dns_rr_t")
end

-- dnsjit.core.object.dns (3)
return Rr

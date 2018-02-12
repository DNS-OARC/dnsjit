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

-- dnsjit.core.tracking
-- Core functions for tracking input sources
--   local tracking = require("dnsjit.core.tracking")
--   local source_id = tracking.src_id()
--
-- Provide a thread safe way of getting an unique ID for an input source,
-- used together with Query ID
-- .I qid
-- to track input sources and queries along the process chain.
module(...,package.seeall)

require("dnsjit.core.tracking_h")
local C = require("ffi").C

Tracking = {}

-- Return the Log object to control logging of this module.
function Tracking.log()
    return C.core_tracking_log()
end

-- Return a new source ID, used for tracking queries.
-- This function is thread safe and uses mutex to keep the ID unique.
-- See also
-- .BR dnsjit.core.query (3)
-- attributes
-- .BR src_id ,
-- .B qr_id
-- and
-- .BR dst_id .
function Tracking.src_id()
    return C.core_tracking_src_id()
end

-- Return a new query ID, used for tracking queries.
-- This function is thread safe and uses mutex to keep the ID unique.
-- .B NOTE
-- usually the input modules keeps an own unique query ID and does not use
-- this function.
-- See also
-- .BR dnsjit.core.query (3)
-- attributes
-- .BR src_id ,
-- .B qr_id
-- and
-- .BR dst_id .
function Tracking.qr_id()
    return C.core_tracking_qr_id()
end

-- Return a new destination ID, used for tracking queries.
-- This function is thread safe and uses mutex to keep the ID unique.
-- See also
-- .BR dnsjit.core.query (3)
-- attributes
-- .BR src_id ,
-- .B qr_id
-- and
-- .BR dst_id .
function Tracking.dst_id()
    return C.core_tracking_dst_id()
end

-- dnsjit.core.query (3)
return Tracking

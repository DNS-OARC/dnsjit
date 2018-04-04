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

-- dnsjit.core.receiver
-- Receiver data structure definition
--   require("dnsjit.core.receiver_h")
--   local C = require("ffi").C
--   C.core_receiver_call(recv_c_function_ptr, recv_c_function_data, query)
--
-- Receiver and receive interfaces and data structure definitions used by
-- input, filter and output modules to pass query objects for processing.
module(...,package.seeall)

-- dnsjit.core.query (3),
-- dnsjit.input.lua (3)
return

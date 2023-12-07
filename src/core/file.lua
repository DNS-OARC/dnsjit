-- Copyright (c) 2018-2023, OARC, Inc.
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

-- dnsjit.core.file
-- OS file operations
--   require("dnsjit.core.file")
--   local ffi = require("ffi")
--   if ffi.C.core_file_exists("path/file") == 0 then
--       ...
--   end
--
-- Module that exposes some file operations that are missing from Lua.
-- .SS C functions
-- .TP
-- core_file_exists(path/filename)
-- Function that takes a string and uses
-- .B stat()
-- to check if that path/filename exists.
-- Returns zero if it exists.
module(...,package.seeall)

require("dnsjit.core.file_h")

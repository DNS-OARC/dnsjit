-- Copyright (c) 2018-2022, OARC, Inc.
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

-- dnsjit.core.loader
-- Dynamic library loader
--   local loader = require("dnsjit.core.loader")
--   loader.load("example-input-zero/zero")
--
-- Module for loading dynamic libraries (.so) in more ways then LuaJIT can.
-- This is mainly used in external modules.
module(...,package.seeall)

require("dnsjit.core.file")
local ffi = require("ffi")
local C = ffi.C

local Loader = {}

-- Search
-- .B package.cpath
-- for the given name and load the first found.
-- If
-- .B global
-- is true (default true if not given) then the loaded symbols will also
-- be available globally.
-- Returns the loaded C library as per
-- .BR ffi.load() .
-- .br
-- The
-- .B ?
-- in each path of
-- .B package.cpath
-- will be replace by the given name, so usually the ".so" part of the
-- library does not need to be given.
-- See
-- .I package.cpath
-- and
-- .I package.loaders
-- in Lua 5.1 for more information.
function Loader.load(name, global)
    if global ~= false then
        global = true
    end
    for path in string.gmatch(package.cpath, "[^;]+") do
        path = path:gsub("?", name)
        if C.core_file_exists(path) == 0 then
            return ffi.load(path, global)
        end
    end
    return ffi.load(name)
end

return Loader

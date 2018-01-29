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

-- dnsjit.core.log
-- Core logging facility
-- .SS Usage to control global log level
--   local log = require("dnsjit.core.log")
--   log:enable("all")
-- .SS Usage in C module
-- Add the log struct into the C module struct with the name
-- .IR log .
--   log_t log;
-- .LP
-- Initialize it with the defaults.
--   static log_t _log_defaults = LOG_T_INIT;
--   self->log = _log_defaults;
-- .SS Bind logging in C module to Lua module
-- TODO
-- .SS Usage in pure Lua module
-- TODO
--
-- Core logging facility used by all modules.
-- .SS Log levels
-- .TP
-- all
-- Keyword to enable/disable all changeable log levels.
-- .TP
-- debug
-- Used for debug information.
-- .TP
-- info
-- Used for informational processing messages.
-- .TP
-- notice
-- Used for messages of that may have impact on processing.
-- .TP
-- warning
-- Used for messages that has impact on processing.
-- .TP
-- critical
-- Used for messages that have severe impact on processing, this level can not be disabled.
-- .TP
-- fatal
-- Used to display a message before stopping all processing and existing, this level can not be disabled.
module(...,package.seeall)

require("dnsjit.core.log_h")
local ffi = require("ffi")
local C = ffi.C
local O = C.core_log()

local Log = {}

-- Create a new Log object.
function Log.new(o)
    if not ffi.istype("log_t", o) then
        error("not a log_t")
    end
    return setmetatable({ _ = o, cb = nil }, { __index = Log })
end

-- Set a callback function to call when the log level is changed.
function Log:cb(func)
    if not type(func) == "function" then
        error("func not function")
    end
    self.cb = func
end

-- Enable specified log level.
function Log:enable(level)
    local struct
    if type(self) == "string" then
        level = self
        struct = O
    else
        struct = self._
    end
    if level == "all" then
        struct.debug = 3;
        struct.info = 3;
        struct.notice = 3;
        struct.warning = 3;
    elseif level == "debug" then
        struct.debug = 3;
    elseif level == "info" then
        struct.info = 3;
    elseif level == "notice" then
        struct.notice = 3;
    elseif level == "warning" then
        struct.warning = 3;
    else
        error("invalid log level: "..level)
    end
    if not self.cb == nil then
        self.cb()
    end
end

-- Disable specified log level.
function Log:disable(level)
    local struct
    if type(self) == "string" then
        level = self
        struct = O
    else
        struct = self._
    end
    if level == "all" then
        struct.debug = 2;
        struct.info = 2;
        struct.notice = 2;
        struct.warning = 2;
    elseif level == "debug" then
        struct.debug = 2;
    elseif level == "info" then
        struct.info = 2;
    elseif level == "notice" then
        struct.notice = 2;
    elseif level == "warning" then
        struct.warning = 2;
    else
        error("invalid log level: "..level)
    end
    if not self.cb == nil then
        self.cb()
    end
end

-- Clear specified log level, which means it will revert back to default or inherited settings.
function Log:clear(level)
    local struct
    if type(self) == "string" then
        level = self
        struct = O
    else
        struct = self._
    end
    if level == "all" then
        struct.debug = 0;
        struct.info = 0;
        struct.notice = 0;
        struct.warning = 0;
    elseif level == "debug" then
        struct.debug = 0;
    elseif level == "info" then
        struct.info = 0;
    elseif level == "notice" then
        struct.notice = 0;
    elseif level == "warning" then
        struct.warning = 0;
    else
        error("invalid log level: "..level)
    end
    if not self.cb == nil then
        self.cb()
    end
end

-- Generate a debug message.
function Log:debug(format, ...)
    if self._.debug == 3 or (O.debug == 3 and self._.debug ~= 2) then
        local info = debug.getinfo(2, "S")
        print(string.format("%s[%d] debug: "..format, info.source, info.linedefined, ...))
    end
end

-- Generate an info message.
function Log:info(format, ...)
    if self._.info == 3 or (O.info == 3 and self._.info ~= 2) then
        local info = debug.getinfo(2, "S")
        print(string.format("%s[%d] info: "..format, info.source, info.linedefined, ...))
    end
end

-- Generate a notice message.
function Log:notice(format, ...)
    if self._.notice == 3 or (O.notice == 3 and self._.notice ~= 2) then
        local info = debug.getinfo(2, "S")
        print(string.format("%s[%d] notice: "..format, info.source, info.linedefined, ...))
    end
end

-- Generate a warning message.
function Log:warning(format, ...)
    if self._.warning == 3 or (O.warning == 3 and self._.warning ~= 2) then
        local info = debug.getinfo(2, "S")
        print(string.format("%s[%d] warning: "..format, info.source, info.linedefined, ...))
    end
end

-- Generate a critical message.
function Log:critical(format, ...)
    local info = debug.getinfo(2, "S")
    print(string.format("%s[%d] critical: "..format, info.source, info.linedefined, ...))
end

-- Generate a fatal message.
function Log:fatal(format, ...)
    local info = debug.getinfo(2, "S")
    error(string.format("%s[%d] fatal: "..format, info.source, info.linedefined, ...))
end

return Log

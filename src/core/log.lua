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

-- dnsjit.core.log
-- Core logging facility
-- .SS Usage to control global log level
--   local log = require("dnsjit.core.log")
--   log.enable("all")
--   log.disable("debug")
-- .SS Usage to control module log level
--   local example = require("example") -- Example as below
--   example.log():enable("all")
--   example.log():disable("debug")
-- .SS Usage to control object instance log level
--   local example = require("example") -- Example as below
--   local obj = example.new()
--   obj:log():enable("all")
--   obj:log():disable("debug")
-- .SS Usage in C module
-- .B NOTE
-- naming of variables and module only globals are required to exactly as
-- described in order for the macros to work;
-- .B self
-- is the pointer to the object instance,
-- .B self->_log
-- is the object instance logging configuration struct,
-- .B _log
-- is the module logging configuration struct.
-- .LP
-- Include logging:
--   #include "core/log.h"
-- .LP
-- Add the logging struct to the module struct:
--   typedef struct example {
--       core_log_t _log;
--       ...
--   } example_t;
-- .LP
-- Add a module logging configuration and a struct default:
--   static core_log_t _log = LOG_T_INIT("example");
--   static example_t _defaults = {
--       LOG_T_INIT_OBJ("example"),
--       ...
--   };
-- .LP
-- Use new/free and/or init/destroy functions (depends if you create the
-- object in Lua or not):
--   example_t* example_new() {
--       example_t* self = calloc(1, sizeof(example_t));
-- .
--       *self = _defaults;
--       ldebug("new()");
-- .
--       return self;
--   }
-- .
--   void example_free(example_t* self) {
--       ldebug("free()");
--       free(self);
--   }
-- .
--   int example_init(example_t* self) {
--       *self = _defaults;
-- .
--       ldebug("init()");
-- .
--       return 0;
--   }
-- .
--   void example_destroy(example_t* self) {
--       ldebug("destroy()");
--       ...
--   }
-- .LP
-- In the Lua part of the C module you need to create a function that
-- returns either the object instance Log or the modules Log.
-- .LP
-- Add C function to get module only Log:
--   core_log_t* example_log() {
--       return &_log;
--   }
-- .LP
-- For the structures metatable add the following function:
--   local ffi = require("ffi")
--   local C = ffi.C
-- .
--   function Example:log()
--       if self == nil then
--           return C.example_log()
--       end
--       return self._log
--   end
-- .SS Usage in pure Lua module
--   local log = require("dnsjit.core.log")
--   local ffi = require("ffi")
--   local C = ffi.C
-- .
--   local Example = {}
--   local module_log = log.new("example")
-- .
--   function Example.new()
--       local self = setmetatable({
--           _log = log.new("example", module_log),
--       }, { __index = Example })
-- .
--       self._log:debug("new()")
-- .
--       return self
--   end
-- .
--   function Example:log()
--       if self == nil then
--           return module_log
--       end
--       return self._log
--   end
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
-- Used for messages that have severe impact on processing, this level can
-- not be disabled.
-- .TP
-- fatal
-- Used to display a message before stopping all processing and existing,
-- this level can not be disabled.
-- .SS C macros
-- .TP
-- Object instance macros
-- The following macros uses
-- .IR &self->_log :
-- .BR ldebug(msg...) ,
-- .BR linfo(msg...) ,
-- .BR lnotice(msg...) ,
-- .BR lwarning(msg...) ,
-- .BR lcritical(msg...) ,
-- .BR lfatal(msg...) .
-- .TP
-- Object pointer instance macros
-- The following macros uses
-- .IR self->_log :
-- .BR lpdebug(msg...) ,
-- .BR lpinfo(msg...) ,
-- .BR lpnotice(msg...) ,
-- .BR lpwarning(msg...) ,
-- .BR lpcritical(msg...) ,
-- .BR lpfatal(msg...) .
-- .TP
-- Module macros
-- The following macros uses
-- .IR &_log :
-- .BR mldebug(msg...) ,
-- .BR mlinfo(msg...) ,
-- .BR mlnotice(msg...) ,
-- .BR mlwarning(msg...) ,
-- .BR mlcritical(msg...) ,
-- .BR mlfatal(msg...) .
-- .TP
-- Global macros
-- The following macros uses the global logging configuration:
-- .BR gldebug(msg...) ,
-- .BR glinfo(msg...) ,
-- .BR glnotice(msg...) ,
-- .BR glwarning(msg...) ,
-- .BR glcritical(msg...) ,
-- .BR glfatal(msg...) .
module(...,package.seeall)

require("dnsjit.core.log_h")
local ffi = require("ffi")
local C = ffi.C
local L = C.core_log_log()

local t_name = "core_log_t"
local core_log_t
local Log = {}

-- Create a new Log object with the given module
-- .I name
-- and an optional shared
-- .I module
-- Log object.
function Log.new(name, module)
    local self
    if ffi.istype(t_name, module) then
        self = core_log_t({ is_obj = 1, module = module.settings })
    else
        self = core_log_t()
    end

    local len = #name
    if len > 31 then
        len = 31
    end
    ffi.copy(self.name, name, len)
    self.name[len] = 0

    return self
end

-- Enable specified log level.
function Log:enable(level)
    if not ffi.istype(t_name, self) then
        level = self
        self = L
    end
    if level == "all" then
        self.settings.debug = 3
        self.settings.info = 3
        self.settings.notice = 3
        self.settings.warning = 3
    elseif level == "debug" then
        self.settings.debug = 3
    elseif level == "info" then
        self.settings.info = 3
    elseif level == "notice" then
        self.settings.notice = 3
    elseif level == "warning" then
        self.settings.warning = 3
    else
        error("invalid log level: "..level)
    end
end

-- Disable specified log level.
function Log:disable(level)
    if not ffi.istype(t_name, self) then
        level = self
        self = L
    end
    if level == "all" then
        self.settings.debug = 2
        self.settings.info = 2
        self.settings.notice = 2
        self.settings.warning = 2
    elseif level == "debug" then
        self.settings.debug = 2
    elseif level == "info" then
        self.settings.info = 2
    elseif level == "notice" then
        self.settings.notice = 2
    elseif level == "warning" then
        self.settings.warning = 2
    else
        error("invalid log level: "..level)
    end
end

-- Clear specified log level, which means it will revert back to default
-- or inherited settings.
function Log:clear(level)
    if not ffi.istype(t_name, self) then
        level = self
        self = L
    end
    if level == "all" then
        self.settings.debug = 0
        self.settings.info = 0
        self.settings.notice = 0
        self.settings.warning = 0
    elseif level == "debug" then
        self.settings.debug = 0
    elseif level == "info" then
        self.settings.info = 0
    elseif level == "notice" then
        self.settings.notice = 0
    elseif level == "warning" then
        self.settings.warning = 0
    else
        error("invalid log level: "..level)
    end
end

-- Enable or disable the displaying of file and line for messages.
function Log:display_file_line(bool)
    if not ffi.istype(t_name, self) then
        bool = self
        self = L
    end
    if bool == true then
        self.settings.display_file_line = 3
    else
        self.settings.display_file_line = 0
    end
end

-- Convert error number to its text representation.
function Log.errstr(errno)
    return ffi.string(C.core_log_errstr(errno))
end

-- Generate a debug message.
function Log.debug(self, ...)
    local format
    if not ffi.istype(t_name, self) then
        format = self
        self = nil
    end
    if not self then
        if L.settings.debug ~= 3 then
            return
        end
    else
        if self.settings.debug ~= 0 then
            if self.settings.debug ~= 3 then
                return
            end
        elseif self.module ~= nil and self.module.debug ~= 0 then
            if self.module.debug ~= 3 then
                return
            end
        elseif L.settings.debug ~= 3 then
            return
        end
    end
    while true do
        if not self then
            if L.settings.display_file_line ~= 3 then
                break
            end
        else
            if self.settings.display_file_line ~= 0 then
                if self.settings.display_file_line ~= 3 then
                    break
                end
            elseif self.module ~= nil and self.module.display_file_line ~= 0 then
                if self.module.display_file_line ~= 3 then
                    break
                end
            elseif L.settings.display_file_line ~= 3 then
                break
            end
        end
        local info = debug.getinfo(2, "S")
        if format then
            C.core_log_debug(self, info.source, info.linedefined, format, ...)
            return
        end
        C.core_log_debug(self, info.source, info.linedefined, ...)
        return
    end

    if format then
        C.core_log_debug(self, nil, 0, format, ...)
        return
    end
    C.core_log_debug(self, nil, 0, ...)
end

-- Generate an info message.
function Log.info(self, ...)
    local format
    if not ffi.istype(t_name, self) then
        format = self
        self = nil
    end
    if not self then
        if L.settings.info ~= 3 then
            return
        end
    else
        if self.settings.info ~= 0 then
            if self.settings.info ~= 3 then
                return
            end
        elseif self.module ~= nil and self.module.info ~= 0 then
            if self.module.info ~= 3 then
                return
            end
        elseif L.settings.info ~= 3 then
            return
        end
    end
    while true do
        if not self then
            if L.settings.display_file_line ~= 3 then
                break
            end
        else
            if self.settings.display_file_line ~= 0 then
                if self.settings.display_file_line ~= 3 then
                    break
                end
            elseif self.module ~= nil and self.module.display_file_line ~= 0 then
                if self.module.display_file_line ~= 3 then
                    break
                end
            elseif L.settings.display_file_line ~= 3 then
                break
            end
        end
        local info = debug.getinfo(2, "S")
        if format then
            C.core_log_info(self, info.source, info.linedefined, format, ...)
            return
        end
        C.core_log_info(self, info.source, info.linedefined, ...)
        return
    end

    if format then
        C.core_log_info(self, nil, 0, format, ...)
        return
    end
    C.core_log_info(self, nil, 0, ...)
end

-- Generate a notice message.
function Log.notice(self, ...)
    local format
    if not ffi.istype(t_name, self) then
        format = self
        self = nil
    end
    if not self then
        if L.settings.notice ~= 3 then
            return
        end
    else
        if self.settings.notice ~= 0 then
            if self.settings.notice ~= 3 then
                return
            end
        elseif self.module ~= nil and self.module.notice ~= 0 then
            if self.module.notice ~= 3 then
                return
            end
        elseif L.settings.notice ~= 3 then
            return
        end
    end
    while true do
        if not self then
            if L.settings.display_file_line ~= 3 then
                break
            end
        else
            if self.settings.display_file_line ~= 0 then
                if self.settings.display_file_line ~= 3 then
                    break
                end
            elseif self.module ~= nil and self.module.display_file_line ~= 0 then
                if self.module.display_file_line ~= 3 then
                    break
                end
            elseif L.settings.display_file_line ~= 3 then
                break
            end
        end
        local info = debug.getinfo(2, "S")
        if format then
            C.core_log_notice(self, info.source, info.linedefined, format, ...)
            return
        end
        C.core_log_notice(self, info.source, info.linedefined, ...)
        return
    end

    if format then
        C.core_log_notice(self, nil, 0, format, ...)
        return
    end
    C.core_log_notice(self, nil, 0, ...)
end

-- Generate a warning message.
function Log.warning(self, ...)
    local format
    if not ffi.istype(t_name, self) then
        format = self
        self = nil
    end
    if not self then
        if L.settings.warning ~= 3 then
            return
        end
    else
        if self.settings.warning ~= 0 then
            if self.settings.warning ~= 3 then
                return
            end
        elseif self.module ~= nil and self.module.warning ~= 0 then
            if self.module.warning ~= 3 then
                return
            end
        elseif L.settings.warning ~= 3 then
            return
        end
    end
    while true do
        if not self then
            if L.settings.display_file_line ~= 3 then
                break
            end
        else
            if self.settings.display_file_line ~= 0 then
                if self.settings.display_file_line ~= 3 then
                    break
                end
            elseif self.module ~= nil and self.module.display_file_line ~= 0 then
                if self.module.display_file_line ~= 3 then
                    break
                end
            elseif L.settings.display_file_line ~= 3 then
                break
            end
        end
        local info = debug.getinfo(2, "S")
        if format then
            C.core_log_warning(self, info.source, info.linedefined, format, ...)
            return
        end
        C.core_log_warning(self, info.source, info.linedefined, ...)
        return
    end

    if format then
        C.core_log_warning(self, nil, 0, format, ...)
        return
    end
    C.core_log_warning(self, nil, 0, ...)
end

-- Generate a critical message.
function Log.critical(self, ...)
    local format
    if not ffi.istype(t_name, self) then
        format = self
        self = nil
    end
    while true do
        if not self then
            if L.settings.display_file_line ~= 3 then
                break
            end
        else
            if self.settings.display_file_line ~= 0 then
                if self.settings.display_file_line ~= 3 then
                    break
                end
            elseif self.module ~= nil and self.module.display_file_line ~= 0 then
                if self.module.display_file_line ~= 3 then
                    break
                end
            elseif L.settings.display_file_line ~= 3 then
                break
            end
        end
        local info = debug.getinfo(2, "S")
        if format then
            C.core_log_critical(self, info.source, info.linedefined, format, ...)
            return
        end
        C.core_log_critical(self, info.source, info.linedefined, ...)
        return
    end

    if format then
        C.core_log_critical(self, nil, 0, format, ...)
        return
    end
    C.core_log_critical(self, nil, 0, ...)
end

-- Generate a fatal message.
function Log.fatal(self, ...)
    local format
    if not ffi.istype(t_name, self) then
        format = self
        self = nil
    end
    while true do
        if not self then
            if L.settings.display_file_line ~= 3 then
                break
            end
        else
            if self.settings.display_file_line ~= 0 then
                if self.settings.display_file_line ~= 3 then
                    break
                end
            elseif self.module ~= nil and self.module.display_file_line ~= 0 then
                if self.module.display_file_line ~= 3 then
                    break
                end
            elseif L.settings.display_file_line ~= 3 then
                break
            end
        end
        local info = debug.getinfo(2, "S")
        if format then
            C.core_log_fatal(self, info.source, info.linedefined, format, ...)
            return
        end
        C.core_log_fatal(self, info.source, info.linedefined, ...)
        return
    end

    if format then
        C.core_log_fatal(self, nil, 0, format, ...)
        return
    end
    C.core_log_fatal(self, nil, 0, ...)
end

core_log_t = ffi.metatype(t_name, { __index = Log })

return Log

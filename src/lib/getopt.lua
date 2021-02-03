-- Copyright (c) 2018-2021, OARC, Inc.
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

-- dnsjit.lib.getopt
-- Parse and handle arguments
--   local getopt = require("dnsjit.lib.getopt").new({
--       { "v", "verbose", 0, "Enable verbosity", "?+" },
--       { nil, "host", "localhost", "Set host", "?" },
--       { "p", nil, 53, "Set port", "?" },
--   })
-- .
--   local left = getopt:parse()
-- .
--   print("host", getopt:val("host"))
--   print("port", getopt:val("p"))
--
-- A "getopt long" implementation to easily handle command line arguments
-- and display usage.
-- An option is the short name (one character), long name,
-- default value (which also defines the type), help text and extensions.
-- Options are by default required, see extensions to change this.
-- .LP
-- The Lua types allowed are
-- .BR boolean ,
-- .BR string ,
-- .BR number .
-- .LP
-- The extensions available are:
-- .TP
-- .B ?
-- Make the option optional.
-- .TP
-- .B *
-- For string and number options this make it possible to specified it
-- multiple times and all values will be returned in a table.
-- .TP
-- .B +
-- For number options this will act as an counter increaser, the value will
-- be the default value + 1 for each time the option is given.
-- .LP
-- Option
-- .I -h
-- and
-- .I --help
-- are automatically added if the option
-- .I --help
-- is not already defined.
-- .SS Attributes
-- .TP
-- left
-- A table that contains the arguments left after parsing, same as returned by
-- .IR parse() .
-- .TP
-- usage_desc
-- A string that describes the usage of the program, if not set then the
-- default will be "
-- .I "program [options...]"
-- ".
module(...,package.seeall)

local log = require("dnsjit.core.log")

local module_log = log.new("lib.getopt")
Getopt = {}

-- Create a new Getopt object.
-- .I args
-- is a table with tables that specifies the options available.
-- Each entry is unpacked and sent to
-- .BR Getopt:add() .
function Getopt.new(args)
    local self = setmetatable({
        left = {},
        usage_desc = nil,
        _opt = {},
        _s2l = {},
        _log = log.new("lib.getopt", module_log),
    }, { __index = Getopt })

    self._log:debug("new()")

    for k, v in pairs(args) do
        local short, long, default, help, extensions = unpack(v)
        self:add(short, long, default, help, extensions)
    end

    return self
end

-- Return the Log object to control logging of this instance or module.
function Getopt:log()
    if self == nil then
        return module_log
    end
    return self._log
end

-- Add an option.
function Getopt:add(short, long, default, help, extensions)
    local optional = false
    local multiple = false
    local counter = false
    local name = long or short

    if type(name) ~= "string" then
        error("long|short) need to be a string")
    elseif name == "" then
        error("name (long|short) needs to be set")
    end

    if self._opt[name] then
        error("option "..name.." alredy exists")
    elseif short and self._s2l[short] then
        error("option "..short.." alredy exists")
    end

    local t = type(default)
    if t ~= "string" and t ~= "number" and t ~= "boolean" then
        error("option "..name..": invalid type "..t)
    end

    if type(extensions) == "string" then
        local n
        for n = 1, extensions:len() do
            local extension = extensions:sub(n, n)
            if extension == "?" then
                optional = true
            elseif extension == "*" then
                multiple = true
            elseif extension == "+" then
                counter = true
            else
                error("option "..name..": invalid extension "..extension)
            end
        end
    end

    self._opt[name] = {
        value = nil,
        short = short,
        long = long,
        type = t,
        default = default,
        help = help,
        optional = optional,
        multiple = multiple,
        counter = counter,
    }
    if long and short then
        self._s2l[short] = long
    elseif short and not long then
        self._s2l[short] = short
    end

    if not self._opt["help"] then
        self._opt["help"] = {
            short = nil,
            long = "help",
            type = "boolean",
            default = false,
            help = "Display this help text",
            optional = true,
        }
        if not self._s2l["h"] then
            self._opt["help"].short = "h"
            self._s2l["h"] = "help"
        end
    end
end

-- Print the usage.
function Getopt:usage()
    if self.usage_desc then
        print("usage: " .. self.usage_desc)
    else
        print("usage: program [options...]")
    end

    local opts = {}
    for k, _ in pairs(self._opt) do
        if k ~= "help" then
            table.insert(opts, k)
        end
    end
    table.sort(opts)
    table.insert(opts, "help")

    for _, k in pairs(opts) do
        local v = self._opt[k]
        local arg
        if v.type == "string" then
            arg = " \""..v.default.."\""
        elseif v.type == "number" and v.counter == false then
            arg = " "..v.default
        else
            arg = ""
        end
        if v.long then
            print("", (v.short and "-"..v.short or "  ").." --"..v.long..arg, v.help)
        else
            print("", "-"..v.short..arg, v.help)
        end
    end
end

-- Parse the options.
-- If
-- .I args
-- is not specified or nil then the global
-- .B arg
-- is used.
-- If
-- .I startn
-- is given, it will start parsing arguments in the table from that position.
-- The default position to start at is 2 for
-- .IR dnsjit ,
-- see
-- .BR dnsjit.core (3).
function Getopt:parse(args, startn)
    if not args then
        args = arg
    end

    local n
    local opt = nil
    local left = {}
    local need_arg = false
    local stop = false
    local name
    for n = startn or 2, table.maxn(args) do
        if need_arg then
            if opt.multiple then
                if opt.value == nil then
                    opt.value = {}
                end
                if opt.type == "number" then
                    table.insert(opt.value, tonumber(args[n]))
                else
                    table.insert(opt.value, args[n])
                end
            else
                if opt.type == "number" then
                    opt.value = tonumber(args[n])
                else
                    opt.value = args[n]
                end
            end
            need_arg = false
        elseif stop or args[n] == "-" then
            table.insert(left, args[n])
        elseif args[n] == "--" then
            stop = true
        elseif args[n]:sub(1, 1) == "-" then
            if args[n]:sub(1, 2) == "--" then
                name = args[n]:sub(3)
            else
                name = args[n]:sub(2)
                if name:len() > 1 then
                    local n2, name2
                    for n2 = 1, name:len() - 1 do
                        name2 = name:sub(n2, n2)
                        opt = self._opt[self._s2l[name2]]
                        if not opt then
                            error("unknown option "..name2)
                        end
                        if opt.type == "number" and opt.counter then
                            if opt.value == nil then
                                opt.value = opt.default
                            end
                            opt.value = opt.value + 1
                        elseif opt.type == "boolean" then
                            if opt.value == nil then
                                opt.value = opt.default
                            end
                            if opt.value then
                                opt.value = false
                            else
                                opt.value = true
                            end
                        else
                            error("invalid short option '"..name2.."' in multioption statement")
                        end
                    end
                    name = name:sub(-1)
                end
            end
            if self._s2l[name] then
                name = self._s2l[name]
            end
            if not self._opt[name] then
                error("unknown option "..name)
            end
            opt = self._opt[name]
            if opt.type == "string" then
                need_arg = true
            elseif opt.type == "number" then
                if opt.counter then
                    if opt.value == nil then
                        opt.value = opt.default
                    end
                    opt.value = opt.value + 1
                else
                    need_arg = true
                end
            elseif opt.type == "boolean" then
                if opt.value == nil then
                    opt.value = opt.default
                end
                if opt.value then
                    opt.value = false
                else
                    opt.value = true
                end
            else
                error("internal error, invalid option type "..opt.type)
            end
        else
            table.insert(left, args[n])
        end
    end

    if need_arg then
        error("option "..name.." needs argument")
    end

    for k, v in pairs(self._opt) do
        if v.optional == false and v.value == nil then
            error("missing required option "..k.."")
        end
    end

    self.left = left
    return left
end

-- Return the value of an option.
function Getopt:val(name)
    local opt = self._opt[name] or self._opt[self._s2l[name]]
    if not opt then
        return
    end
    if opt.value == nil then
        return opt.default
    else
        return opt.value
    end
end

-- dnsjit.core (3)
return Getopt

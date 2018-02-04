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

-- dnsjit.lib.parseconf
-- Parse simple config files
--   local conf = require("dnsjit.lib.parseconf").new()
--   conf:func("config_name", function(k,...)
--       print(k,...)
--   end)
--   conf:parse(file)
--   print(conf:val("another_config_name"))
--
-- This module parses simple config files that are based on the config
-- syntax of DSC, drool and parseconf helper library.
-- Each config begins with a
-- .B name
-- followed by
-- .B options
-- and ends with a
-- .BR ; .
-- Multiple configs can be given on the same line.
-- Valid option types are
-- .IR number ,
-- .IR float ,
-- .IR string ,
-- .IR "quoted string" .
-- Comments can be added by prefixing the comment with
-- .BR # .
-- .SS Example
--   # Comment
--   number 12345;
--   float 123.456;
--   string string string;
--   quoted_string "string string string";
--   multi config; on one line;
module(...,package.seeall)

Parseconf = {}

-- Create a new Parseconf object.
function Parseconf.new()
    return setmetatable({ conf = {}, cf = {} }, { __index = Parseconf })
end

-- Set a function to call when config
-- .I name
-- is found.
function Parseconf:func(name, func)
    self.cf[name] = func
end

function Parseconf:part(l, n)
    local p
    p = l:match("^(%d+)[%s;]", n)
    if p then
        return p, tonumber(p)
    end
    p = l:match("^(%d+%.%d+)[%s;]", n)
    if p then
        return p, tonumber(p)
    end
    p = l:match("^([^%s;]+)[%s;]", n)
    if p then
        return p, p
    end
    p = l:match("^(\"[^\"]+\")[%s;]", n)
    if p then
        return p, p:sub(2, -2)
    end
end

function Parseconf:next(l, n)
    local eol = l:match("^%s*;%s*", n)
    if eol then
        return true, eol
    end
    local ws = l:match("^%s+", n)
    if ws then
        return ws
    end
    return false
end

-- Parse the given file.
function Parseconf:file(fn)
    local ln, l, c, e, m
    ln = 1
    for l in io.lines(fn) do
        c = l:find("#")
        if c then
            l = l:sub(1, c - 1)
        end
        e, m = pcall(self.line, self, l)
        if e == false then
            error("parse error in "..fn.."["..ln.."]: "..m)
        end
        ln = ln + 1
    end
end

-- Parse the given line.
function Parseconf:line(l)
    local n, p, v, va, c, ws, n, eol
    n = 1
    while n <= l:len() do
        c = nil
        va = {}
        while true do
            p, v = self:part(l, n)
            if not p then
                error("invalid config at character "..n..": "..l:sub(n))
            end
            if not c then
                c = p
            else
                table.insert(va, v)
            end
            n = n + p:len()
            ws, eol = self:next(l, n)
            if ws == true then
                if eol then
                    n = n + eol:len()
                end
                break
            elseif ws == false then
                error("invalid config at character "..n..": "..l:sub(n))
            end
            n = n + ws:len()
        end
        if self.cf[c] then
            self.cf[c](c, unpack(va))
        else
            self.conf[c] = va
        end
    end
end

-- Get the value of a config
-- .IR name .
function Parseconf:val(name)
    return self.conf[name]
end

return Parseconf

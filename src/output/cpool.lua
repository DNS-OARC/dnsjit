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

-- dnsjit.output.cpool
-- Send queries to a target by emulating clients (a client pool)
--   local output = require("dnsjit.output.cpool").new(host, port)
--   input:receiver(output)
--   output:start()
--   ...
--   output:stop()
--
-- Output module to send queries to a target with options to emulate a set
-- number of clients, send queries over other protocols and more.
-- This is handled by starting another thread and passing the queries to it
-- via a queue and using EV as the event engine to send them.
-- .LP
-- .B NOTE
-- there is currently no functionality implemented to retrieve the responses.
module(...,package.seeall)

local ch = require("dnsjit.core.chelpers")
local log = require("dnsjit.core.log")
require("dnsjit.output.cpool_h")
local ffi = require("ffi")
local C = ffi.C

local type = "output_cpool_t"
local struct
local mt = {
    __gc = function(self)
        if ffi.istype(type, self) then
            C.output_cpool_destroy(self)
        end
    end,
    __index = {
        new = function(host, port)
            local self = struct()
            if not self then
                error("oom")
            end
            if ffi.istype(type, self) then
                C.output_cpool_init(self, host, port)
                return self
            end
        end
    }
}
struct = ffi.metatype(type, mt)

local Cpool = {}

-- Create a new Cpool output.
function Cpool.new(host, port)
    local o = struct.new(host, port)
    local log = log.new(o.log)
    log:cb(function ()
        C.output_cpool_updatelog(o)
    end)
    log:debug("new()")
    C.output_cpool_updatelog(o)
    return setmetatable({
        _ = o,
        log = log,
    }, {__index = Cpool})
end

-- Set the maximum clients to emulate, if
-- .I max
-- is not specified then return the current maximum clients.
function Cpool:max_clients(max)
    if max == nil then
        return C.output_cpool_max_clients(self._)
    end
    return ch.z2n(C.output_cpool_set_max_clients(self._, max))
end

-- Set the client ttl (a float/double), if
-- .I ttl
-- is not specified then return the current client ttl.
-- This TTL is used to timeout clients and is specified as fractions of
-- seconds meaning 0.1 is 100 ms.
function Cpool:client_ttl(ttl)
    if ttl == nil then
        return C.output_cpool_client_ttl(self._)
    end
    return ch.z2n(C.output_cpool_set_client_ttl(self._, ttl))
end

-- Set the maximum clients to keep around to reuse later on, if
-- .I reuse
-- is not specified then return the current maximum clients to reuse.
function Cpool:max_reuse_clients(reuse)
    if reuse == nil then
        return C.output_cpool_max_reuse_clients(self._)
    end
    return ch.z2n(C.output_cpool_set_max_reuse_clients(self._, reuse))
end

-- Enable (true) or disable (false) not waiting for a reply, if
-- .I bool
-- is not specified then return if skipping reply is on (true) or off (false).
function Cpool:skip_reply(bool)
    if bool == nil then
        return ch.i2b(C.output_cpool_skip_reply(self._))
    end
    local b = ch.b2i(bool)
    if b == nil then
        return 1
    end
    return ch.z2n(C.output_cpool_set_skip_reply(self._, b))
end

-- Set the protocol to send queries as, if
-- .I type
-- is not specified then return the current way to send queries.
-- Valid ways are;
-- .IR original ,
-- .IR udp ,
-- .IR tcp .
function Cpool:sendas(type)
    if type == nil then
        return C.output_cpool_sendas(self._)
    elseif type == "original" then
        return ch.z2n(C.output_cpool_set_sendas_original(self._))
    elseif type == "udp" then
        return ch.z2n(C.output_cpool_set_sendas_udp(self._))
    elseif type == "tcp" then
        return ch.z2n(C.output_cpool_set_sendas_tcp(self._))
    end
    return 1
end

-- Enable (true) or disable (false) dry run mode, if
-- .I bool
-- is not specified then return if dry run is on (true) or off (false).
function Cpool:dry_run(bool)
    if bool == nil then
        return ch.i2b(C.output_cpool_dry_run(self._))
    end
    local b = ch.b2i(bool)
    if b == nil then
        return 1
    end
    return ch.z2n(C.output_cpool_set_dry_run(self._, b))
end

-- Start the processing of queries sent to the queue.
function Cpool:start()
    return ch.z2n(C.output_cpool_start(self._))
end

-- Stop the processing of queries.
function Cpool:stop()
    return ch.z2n(C.output_cpool_stop(self._))
end

function Cpool:receive()
    if self.ishandler then
        error("is handler")
    end
    self.log:debug("receive()")
    return C.output_cpool_receiver(), self._
end

return Cpool
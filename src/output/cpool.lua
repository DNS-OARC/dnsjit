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
require("dnsjit.output.cpool_h")
local ffi = require("ffi")
local C = ffi.C

local t_name = "output_cpool_t"
local output_cpool_t = ffi.typeof(t_name)
local Cpool = {}

-- Create a new Cpool output for the target
-- .I host
-- and
-- .I port
-- with an optional queue size.
function Cpool.new(host, port, queue_size)
    if queue_size == nil then
        queue_size = 0
    end
    local self = {
        _receiver = nil,
        obj = output_cpool_t(),
    }
    C.output_cpool_init(self.obj, host, port, queue_size)
    ffi.gc(self.obj, C.output_cpool_destroy)
    return setmetatable(self, { __index = Cpool })
end

-- Return the Log object to control logging of this instance or module.
function Cpool:log()
    if self == nil then
        return C.output_cpool_log()
    end
    return self.obj._log
end

-- Set the maximum clients to emulate, if
-- .I max
-- is not specified then return the current maximum clients.
function Cpool:max_clients(max)
    if max == nil then
        return C.output_cpool_max_clients(self.obj)
    end
    return ch.z2n(C.output_cpool_set_max_clients(self.obj, max))
end

-- Set the client ttl (a float/double), if
-- .I ttl
-- is not specified then return the current client ttl.
-- This TTL is used to timeout clients and is specified as fractions of
-- seconds meaning 0.1 is 100 ms.
function Cpool:client_ttl(ttl)
    if ttl == nil then
        return C.output_cpool_client_ttl(self.obj)
    end
    return ch.z2n(C.output_cpool_set_client_ttl(self.obj, ttl))
end

-- Set the maximum clients to keep around to reuse later on, if
-- .I reuse
-- is not specified then return the current maximum clients to reuse.
function Cpool:max_reuse_clients(reuse)
    if reuse == nil then
        return C.output_cpool_max_reuse_clients(self.obj)
    end
    return ch.z2n(C.output_cpool_set_max_reuse_clients(self.obj, reuse))
end

-- Enable (true) or disable (false) not waiting for a reply, if
-- .I bool
-- is not specified then return if skipping reply is on (true) or off (false).
function Cpool:skip_reply(bool)
    if bool == nil then
        return ch.i2b(C.output_cpool_skip_reply(self.obj))
    end
    local b = ch.b2i(bool)
    if b == nil then
        return 1
    end
    return ch.z2n(C.output_cpool_set_skip_reply(self.obj, b))
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
        return C.output_cpool_sendas(self.obj)
    elseif type == "original" then
        return ch.z2n(C.output_cpool_set_sendas_original(self.obj))
    elseif type == "udp" then
        return ch.z2n(C.output_cpool_set_sendas_udp(self.obj))
    elseif type == "tcp" then
        return ch.z2n(C.output_cpool_set_sendas_tcp(self.obj))
    end
    return 1
end

-- Enable (true) or disable (false) dry run mode, if
-- .I bool
-- is not specified then return if dry run is on (true) or off (false).
function Cpool:dry_run(bool)
    if bool == nil then
        return ch.i2b(C.output_cpool_dry_run(self.obj))
    end
    local b = ch.b2i(bool)
    if b == nil then
        return 1
    end
    return ch.z2n(C.output_cpool_set_dry_run(self.obj, b))
end

-- Start the processing of queries sent to the queue.
function Cpool:start()
    return ch.z2n(C.output_cpool_start(self.obj))
end

-- Stop the processing of queries.
function Cpool:stop()
    return ch.z2n(C.output_cpool_stop(self.obj))
end

-- Set the receiver to pass queries and responses to.
function Cpool:receiver(o)
    self.obj._log:debug("receiver()")
    self.obj.recv, self.obj.ctx = o:receive()
    self._receiver = o
end

function Cpool:receive()
    if self.ishandler then
        error("is handler")
    end
    self.obj._log:debug("receive()")
    return C.output_cpool_receiver(), self.obj
end

return Cpool

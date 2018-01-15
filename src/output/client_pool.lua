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

module(...,package.seeall)

local log = require("dnsjit.core.log")
require("dnsjit.output.client_pool_h")
local ffi = require("ffi")
local C = ffi.C

local type = "output_client_pool_t"
local struct
local mt = {
    __gc = function(self)
        if ffi.istype(type, self) then
            C.output_client_pool_destroy(self)
        end
    end,
    __index = {
        new = function(host, port)
            local self = struct()
            if not self then
                error("oom")
            end
            if ffi.istype(type, self) then
                C.output_client_pool_init(self, host, port)
                return self
            end
        end
    }
}
struct = ffi.metatype(type, mt)

local ClientPool = {}

function ClientPool.new(host, port)
    local o = struct.new(host, port)
    local log = log.new(o.log)
    log:cb(function ()
        C.output_client_pool_updatelog(o)
    end)
    log:debug("new()")
    C.output_client_pool_updatelog(o)
    return setmetatable({
        _ = o,
        log = log,
    }, {__index = ClientPool})
end

function bool2int(bool)
    if bool == true then
        return 1
    elseif bool == false then
        return 0
    end
end

function int2bool(int)
    if int == 0 then
        return false
    end
    return true
end

function zero2none(int)
    if not int == 0 then
        return int
    end
end

function ClientPool:max_clients(max)
    if max == nil then
        return C.output_client_pool_max_clients(self._)
    end
    return zero2none(C.output_client_pool_set_max_clients(self._, max))
end

function ClientPool:client_ttl(ttl)
    if ttl == nil then
        return C.output_client_pool_client_ttl(self._)
    end
    return zero2none(C.output_client_pool_set_client_ttl(self._, ttl))
end

function ClientPool:max_reuse_clients(reuse)
    if reuse == nil then
        return C.output_client_pool_max_reuse_clients(self._)
    end
    return zero2none(C.output_client_pool_set_max_reuse_clients(self._, reuse))
end

function ClientPool:skip_reply(bool)
    if bool == nil then
        return int2bool(C.output_client_pool_skip_reply(self._))
    end
    local b = bool2int(bool)
    if b == nil then
        return 1
    end
    return zero2none(C.output_client_pool_set_skip_reply(self._, b))
end

function ClientPool:sendas(type)
    if type == nil then
        return C.output_client_pool_sendas(self._)
    elseif type == "original" then
        return zero2none(C.output_client_pool_set_sendas_original(self._))
    elseif type == "udp" then
        return zero2none(C.output_client_pool_set_sendas_udp(self._))
    elseif type == "tcp" then
        return zero2none(C.output_client_pool_set_sendas_tcp(self._))
    end
    return 1
end

function ClientPool:dry_run(bool)
    if bool == nil then
        return int2bool(C.output_client_pool_dry_run(self._))
    end
    local b = bool2int(bool)
    if b == nil then
        return 1
    end
    return zero2none(C.output_client_pool_set_dry_run(self._, b))
end

function ClientPool:start()
    return C.output_client_pool_start(self._)
end

function ClientPool:stop()
    return C.output_client_pool_stop(self._)
end

function ClientPool:receive()
    if self.ishandler then
        error("is handler")
    end
    self.log:debug("receive()")
    return C.output_client_pool_receiver(), self._
end

return ClientPool

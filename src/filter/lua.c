/*
 * Copyright (c) 2018, OARC, Inc.
 * All rights reserved.
 *
 * This file is part of dnsjit.
 *
 * dnsjit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dnsjit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "filter/lua.h"

#include <lualib.h>
#include <lauxlib.h>

static filter_lua_t _defaults = {
    LOG_T_INIT,
    0, 0, 0, 0
};

int filter_lua_init(filter_lua_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("init %p", self);

    *self = _defaults;

    if (!(self->L = luaL_newstate())) {
        return 1;
    }
    luaL_openlibs(self->L);
    lua_newtable(self->L);
    lua_setglobal(self->L, "FILTER_LUA_ARGS");
    if (luaL_dostring(self->L, "FILTER_LUA = require(\"dnsjit.filter.lua\").handler()")) {
        lcritical("%s", lua_tostring(self->L, -1));
        lua_pop(self->L, 1);
    }

    return 0;
}

int filter_lua_destroy(filter_lua_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy %p", self);

    lua_close(self->L);

    return 0;
}

int filter_lua_func(filter_lua_t* self, const char* bc, size_t len)
{
    if (!self || !bc || !len) {
        return 1;
    }

    ldebug("func %p %p %lu", self, bc, len);

    if (self->recv) {
        ldebug("func recv %p %p", self->recv, self->robj);
        lua_pushlightuserdata(self->L, self->recv);
        lua_setglobal(self->L, "FILTER_LUA_RECV");
        lua_pushlightuserdata(self->L, self->robj);
        lua_setglobal(self->L, "FILTER_LUA_ROBJ");
    }
    lua_pushlstring(self->L, bc, len);
    lua_setglobal(self->L, "FILTER_LUA_BYTECODE");
    if (luaL_dostring(self->L, "FILTER_LUA:decompile()")) {
        lcritical("%s", lua_tostring(self->L, -1));
        lua_pop(self->L, 1);
        return 1;
    }

    return 0;
}

int filter_lua_push_string(filter_lua_t* self, const char* s, size_t l)
{
    if (!self || !self->L || !s) {
        return 1;
    }

    lua_getglobal(self->L, "FILTER_LUA_ARGS");
    lua_pushlstring(self->L, s, l);
    lua_rawseti(self->L, -2, self->args);
    self->args++;

    return 0;
}

int filter_lua_push_integer(filter_lua_t* self, int i)
{
    if (!self || !self->L) {
        return 1;
    }

    lua_getglobal(self->L, "FILTER_LUA_ARGS");
    lua_pushinteger(self->L, i);
    lua_rawseti(self->L, -2, self->args);
    self->args++;

    return 0;
}

int filter_lua_push_double(filter_lua_t* self, double d)
{
    if (!self || !self->L) {
        return 1;
    }

    lua_getglobal(self->L, "FILTER_LUA_ARGS");
    lua_pushnumber(self->L, d);
    lua_rawseti(self->L, -2, self->args);
    self->args++;

    return 0;
}

static int _receive(void* robj, query_t* q)
{
    filter_lua_t* self = (filter_lua_t*)robj;

    if (!self || !q) {
        query_free(q);
        return 1;
    }

    ldebug("receive %p", q);

    lua_pushlightuserdata(self->L, q);
    lua_setglobal(self->L, "FILTER_LUA_QUERY");
    if (luaL_dostring(self->L, "FILTER_LUA:run()")) {
        lcritical("%s", lua_tostring(self->L, -1));
        lua_pop(self->L, 1);
        return 1;
    }

    return 0;
}

receiver_t filter_lua_receiver()
{
    return _receive;
}

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

#include "filter/coro.h"

#include <lualib.h>
#include <lauxlib.h>

static core_log_t    _log      = LOG_T_INIT("filter.coro");
static filter_coro_t _defaults = {
    LOG_T_INIT_OBJ("filter.coro"),
    0, 0, 0, 0, 0
};

core_log_t* filter_coro_log()
{
    return &_log;
}

int filter_coro_init(filter_coro_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    return 0;
}

int filter_coro_destroy(filter_coro_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    return 0;
}

lua_State* _T = 0;

int filter_coro_set_thread(filter_coro_t* self)
{
    if (!self || !_T || self->T) {
        return 1;
    }

    ldebug("pickup thread %p", _T);
    self->T = _T;
    _T      = 0;

    return 0;
}

int filter_coro_clear_thread(filter_coro_t* self)
{
    if (!self) {
        return 1;
    }

    self->T = 0;

    return 0;
}

int filter_coro_store_thread(lua_State* L)
{
    luaL_checktype(L, 1, LUA_TTHREAD);
    _T = lua_tothread(L, 1);

    mldebug("store thread %p", _T);

    return 0;
}

const core_object_t* filter_coro_get(filter_coro_t* self)
{
    return self ? self->obj : 0;
}

static int _receive(void* ctx, const core_object_t* obj)
{
    filter_coro_t* self = (filter_coro_t*)ctx;
    int            ret;

    if (!self || !obj) {
        return 1;
    }

    self->obj = obj;
    if ((ret = lua_resume(self->T, 0)) && ret != LUA_YIELD) {
        lfatal("%s", lua_tostring(self->T, -1));
    }
    self->obj = 0;

    return 1;
}

core_receiver_t filter_coro_receiver()
{
    return _receive;
}

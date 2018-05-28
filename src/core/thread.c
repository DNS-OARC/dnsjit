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

#include "globals.h"
#include "core/thread.h"

#include <string.h>
#include <lualib.h>
#include <lauxlib.h>

static core_log_t    _log      = LOG_T_INIT("core.thread");
static core_thread_t _defaults = {
    LOG_T_INIT_OBJ("core.thread"),
    0, 0, 0, 0,
    PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER,
    0, 0
};

core_log_t* core_thread_log()
{
    return &_log;
}

int core_thread_init(core_thread_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    return 0;
}

int core_thread_destroy(core_thread_t* self)
{
    core_thread_item_t* item;

    if (!self) {
        return 1;
    }

    ldebug("destroy");

    free(self->bytecode);
    while ((item = self->stack)) {
        self->stack = item->next;
        free(item);
    }

    return 0;
}

static void* _thread(void* vp)
{
    core_thread_t* self = (core_thread_t*)vp;
    lua_State*     L;

    // TODO: move to dnsjit_newstate()
    L = luaL_newstate();
    luaL_openlibs(L);
    dnsjit_globals(L);

    lua_getfield(L, LUA_GLOBALSINDEX, "require");
    lua_pushstring(L, "dnsjit.core.thread");
    if (lua_pcall(L, 1, 1, 0)) {
        mlcritical("%s", lua_tostring(L, -1));
        lua_close(L);
        return 0;
    }
    lua_getfield(L, -1, "_in_thread");
    lua_pushlightuserdata(L, (void*)self);
    lua_pushlstring(L, self->bytecode, self->bytecode_len);
    if (lua_pcall(L, 2, 0, 0)) {
        mlcritical("%s", lua_tostring(L, -1));
        lua_close(L);
        return 0;
    }

    lua_close(L);
    return 0;
}

int core_thread_start(core_thread_t* self, const char* bytecode, size_t len)
{
    if (!self || self->bytecode) {
        return 1;
    }

    if (!(self->bytecode = malloc(len))) {
        return 1;
    }
    memcpy(self->bytecode, bytecode, len);
    self->bytecode_len = len;

    if (pthread_create(&self->thr_id, 0, _thread, (void*)self)) {
        return 1;
    }

    return 0;
}

int core_thread_stop(core_thread_t* self)
{
    if (!self) {
        return 1;
    }

    if (pthread_join(self->thr_id, 0)) {
        return 1;
    }

    return 0;
}

int core_thread_push(core_thread_t* self, void* ptr, const char* type, size_t type_len, const char* module, size_t module_len)
{
    core_thread_item_t* item;

    if (!self || !ptr || !type || !type_len || !module || !module_len) {
        return 1;
    }

    if (!(item = malloc(sizeof(core_thread_item_t) + type_len + module_len + 2))) {
        return 1;
    }
    item->next = 0;
    item->ptr  = ptr;
    item->type = ((void*)item) + sizeof(core_thread_item_t);
    memcpy(item->type, type, type_len);
    item->type[type_len] = 0;
    item->module         = item->type + type_len + 1;
    memcpy(item->module, module, module_len);
    item->module[module_len] = 0;

    if (pthread_mutex_lock(&self->lock)) {
        lfatal("mutex lock failed");
    }
    if (!self->last) {
        self->stack = self->last = item;
    } else {
        self->last->next = item;
    }
    if (pthread_cond_signal(&self->cond)) {
        lfatal("cond signal failed");
    }
    if (pthread_mutex_unlock(&self->lock)) {
        lfatal("mutex unlock failed");
    }

    return 0;
}

const core_thread_item_t* core_thread_pop(core_thread_t* self)
{
    if (!self) {
        return 0;
    }

    if (pthread_mutex_lock(&self->lock)) {
        lfatal("mutex lock failed");
    }
    if (!self->at) {
        while (!self->stack) {
            if (pthread_cond_wait(&self->cond, &self->lock)) {
                lfatal("cond wait failed");
            }
        }
        self->at = self->stack;
    } else {
        while (!self->at->next) {
            if (pthread_cond_wait(&self->cond, &self->lock)) {
                lfatal("cond wait failed");
            }
        }
        self->at = self->at->next;
    }
    if (pthread_mutex_unlock(&self->lock)) {
        lfatal("mutex unlock failed");
    }

    return self->at;
}
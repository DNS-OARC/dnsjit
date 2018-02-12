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

#include "filter/thread.h"

#include <pthread.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <string.h>
#include <stdlib.h>

static core_log_t      _log      = LOG_T_INIT("filter.thread");
static filter_thread_t _defaults = {
    LOG_T_INIT_OBJ("filter.thread"),
    0, 0, 0, 0, 0, 0
};
static core_query_t _stop;

core_log_t* filter_thread_log()
{
    return &_log;
}

int filter_thread_init(filter_thread_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    return 0;
}

static void _flush(void* v)
{
    core_query_free((core_query_t*)v);
}

int filter_thread_destroy(filter_thread_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    if (self->have_id) {
        filter_thread_stop(self);
        filter_thread_join(self);
        free(self->id);
    }
    if (self->my_queues && self->qin) {
        sllq_flush(self->qin, _flush);
        sllq_destroy(self->qin);
        sllq_free(self->qin);
    }

    return 0;
}

struct _ctx {
    char*           bc;
    size_t          len;
    sllq_t*         qin;
    core_receiver_t recv;
    void*           robj;
};

static void* _thread(void* v)
{
    lua_State*   L;
    struct _ctx* ctx = (struct _ctx*)v;

    if (!ctx || !ctx->bc) {
        free(ctx);
        return 0;
    }

    gldebug("thread %lu", pthread_self());
    L = luaL_newstate();
    luaL_openlibs(L);
    lua_pushlstring(L, ctx->bc, ctx->len);
    lua_setglobal(L, "THREAD_BYTECODE");
    lua_pushlightuserdata(L, ctx->qin);
    lua_setglobal(L, "THREAD_SLLQ_IN");
    if (ctx->recv) {
        lua_pushlightuserdata(L, ctx->recv);
        lua_setglobal(L, "THREAD_RECV");
        lua_pushlightuserdata(L, ctx->robj);
        lua_setglobal(L, "THREAD_ROBJ");
    }
    if (luaL_dostring(L, "require(\"dnsjit.filter.thread\").new():run()")) {
        glcritical("thread %lu: %s", pthread_self(), lua_tostring(L, -1));
        lua_pop(L, 1);
    }
    lua_close(L);

    free(ctx->bc);
    free(ctx);
    return 0;
}

int filter_thread_create(filter_thread_t* self, const char* bc, size_t len)
{
    struct _ctx* ctx;

    if (!self || !bc || !len || self->have_id) {
        return 1;
    }

    ldebug("create %p %lu", bc, len);

    if (!self->id) {
        if (!(self->id = malloc(sizeof(pthread_t)))) {
            return 1;
        }
    }

    if (!(self->qin = sllq_new())) {
        return 1;
    }
    sllq_set_size(self->qin, 8);
    sllq_init(self->qin);
    self->my_queues = 1;

    if (!(ctx = malloc(sizeof(struct _ctx)))) {
        return 1;
    }
    if (!(ctx->bc = malloc(len))) {
        free(ctx);
        return 1;
    }
    memcpy(ctx->bc, bc, len);
    ctx->len  = len;
    ctx->qin  = self->qin;
    ctx->recv = self->recv;
    ctx->robj = self->robj;

    ldebug("create qin %p", self->qin);

    if (pthread_create(self->id, 0, _thread, (void*)ctx)) {
        free(ctx->bc);
        free(ctx);
        return 1;
    }
    self->have_id = 1;

    ldebug("create id %lu", *self->id);

    return 0;
}

int filter_thread_join(filter_thread_t* self)
{
    if (!self || !self->have_id) {
        return 1;
    }

    ldebug("join %lu", *self->id);

    if (pthread_join(*self->id, 0)) {
        return 1;
    }
    self->have_id = 0;

    return 0;
}

int filter_thread_stop(filter_thread_t* self)
{
    int             err;
    struct timespec ts;

    if (!self || !self->have_id) {
        return 1;
    }

    ldebug("stop");

    err = SLLQ_EAGAIN;
    while (err == SLLQ_EAGAIN || err == SLLQ_ETIMEDOUT || err == SLLQ_FULL) {
        if (clock_gettime(CLOCK_REALTIME, &ts)) {
            return 1;
        }
        ts.tv_nsec += 200000000;
        if (ts.tv_nsec > 999999999) {
            ts.tv_sec += ts.tv_nsec / 1000000000;
            ts.tv_nsec %= 1000000000;
        }

        err = sllq_push(self->qin, (void*)&_stop, &ts);
    }

    ldebug("stopped");

    return 0;
}

static int _receive(void* robj, core_query_t* q)
{
    filter_thread_t* self = (filter_thread_t*)robj;
    core_query_t*    copy;
    int              err;
    struct timespec  ts;

    if (!self || !q || !(copy = core_query_copy(q))) {
        core_query_free(q);
        return 1;
    }

    ldebug("push q %p copy %p", q, copy);

    err = SLLQ_EAGAIN;
    while (err == SLLQ_EAGAIN || err == SLLQ_ETIMEDOUT || err == SLLQ_FULL) {
        if (clock_gettime(CLOCK_REALTIME, &ts)) {
            core_query_free(copy);
            core_query_free(q);
            return 1;
        }
        ts.tv_nsec += 200000000;
        if (ts.tv_nsec > 999999999) {
            ts.tv_sec += ts.tv_nsec / 1000000000;
            ts.tv_nsec %= 1000000000;
        }

        err = sllq_push(self->qin, (void*)copy, &ts);
    }

    ldebug("pushed q %p", q);

    core_query_free(q);
    return 0;
}

core_receiver_t filter_thread_receiver()
{
    return _receive;
}

core_query_t* filter_thread_recv(filter_thread_t* self)
{
    core_query_t*   q = 0;
    int             err;
    struct timespec ts;

    if (!self) {
        return 0;
    }

    ldebug("recv");

    err = SLLQ_EAGAIN;
    while (err == SLLQ_EAGAIN || err == SLLQ_ETIMEDOUT || err == SLLQ_EMPTY) {
        if (clock_gettime(CLOCK_REALTIME, &ts)) {
            return 0;
        }
        ts.tv_nsec += 200000000;
        if (ts.tv_nsec > 999999999) {
            ts.tv_sec += ts.tv_nsec / 1000000000;
            ts.tv_nsec %= 1000000000;
        }

        err = sllq_shift(self->qin, (void**)&q, &ts);
    }

    if (q == &_stop) {
        ldebug("recv stop");
        return 0;
    }

    ldebug("recv q %p", q);
    return q;
}

int filter_thread_send(filter_thread_t* self, core_query_t* q)
{
    core_query_t* copy;

    if (!self || !q || !self->recv) {
        return 1;
    }

    if (!(copy = core_query_copy(q))) {
        return 1;
    }

    ldebug("send q %p copy %p", q, copy);
    self->recv(self->robj, copy);

    return 0;
}

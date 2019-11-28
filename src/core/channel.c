/*
 * Copyright (c) 2018-2019, OARC, Inc.
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

#include "core/channel.h"
#include "core/assert.h"

#include <sched.h>

static core_log_t     _log      = LOG_T_INIT("core.channel");
static core_channel_t _defaults = {
    LOG_T_INIT_OBJ("core.channel"),
    0, { 0 }, 0, 0,
    0, 0
};

core_log_t* core_channel_log()
{
    return &_log;
}

static inline bool _is_pow2(size_t num)
{
    while (num != 1) {
        if (num % 2 != 0)
            return false;
        num = num / 2;
    }
    return true;
}

void core_channel_init(core_channel_t* self, size_t capacity)
{
    mlassert_self();
    if (capacity < 4 || !_is_pow2(capacity)) {
        mlfatal("invalid capacity");
    }

    *self          = _defaults;
    self->capacity = capacity;

    lfatal_oom(self->ring_buf = malloc(sizeof(ck_ring_buffer_t) * capacity));
    ck_ring_init(&self->ring, capacity);
}

void core_channel_destroy(core_channel_t* self)
{
    mlassert_self();
    free(self->ring_buf);
}

void core_channel_put(core_channel_t* self, const void* obj)
{
    mlassert_self();
    lassert(self->ring_buf, "ring_buf is nil");

    while (!ck_ring_enqueue_spsc(&self->ring, self->ring_buf, (void*)obj)) {
        sched_yield();
    }
}

int core_channel_try_put(core_channel_t* self, const void* obj)
{
    mlassert_self();
    lassert(self->ring_buf, "ring_buf is nil");

    if (!ck_ring_enqueue_spsc(&self->ring, self->ring_buf, (void*)obj)) {
        return -1;
    }

    return 0;
}

void* core_channel_get(core_channel_t* self)
{
    void* obj = 0;
    mlassert_self();
    lassert(self->ring_buf, "ring_buf is nil");

    while (!ck_ring_dequeue_spsc(&self->ring, self->ring_buf, &obj)) {
        sched_yield();
        if (ck_pr_load_int(&self->closed)) {
            linfo("channel closed");
            return 0;
        }
    }

    return obj;
}

void* core_channel_try_get(core_channel_t* self)
{
    void* obj = 0;
    mlassert_self();
    lassert(self->ring_buf, "ring_buf is nil");

    if (!ck_ring_dequeue_spsc(&self->ring, self->ring_buf, &obj)) {
        return 0;
    }

    return obj;
}

int core_channel_size(core_channel_t* self)
{
    mlassert_self();
    return ck_ring_size(&self->ring);
}

bool core_channel_full(core_channel_t* self)
{
    mlassert_self();
    if (ck_ring_size(&self->ring) < self->capacity) {
        return false;
    }
    return true;
}

void core_channel_close(core_channel_t* self)
{
    mlassert_self();
    ck_pr_store_int(&self->closed, 1);
}

core_receiver_t core_channel_receiver()
{
    return (core_receiver_t)core_channel_put;
}

void core_channel_run(core_channel_t* self)
{
    void* obj = 0;
    mlassert_self();
    lassert(self->ring_buf, "ring_buf is nil");
    if (!self->recv) {
        lfatal("no receiver set");
    }

    for (;;) {
        while (!ck_ring_dequeue_spsc(&self->ring, self->ring_buf, &obj)) {
            sched_yield();
            if (ck_pr_load_int(&self->closed)) {
                linfo("channel closed");
                return;
            }
        }
        self->recv(self->ctx, obj);
    }
}

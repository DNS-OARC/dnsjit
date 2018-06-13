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

#include "core/channel.h"
#include "core/assert.h"

#include <sched.h>

static core_log_t     _log      = LOG_T_INIT("core.channel");
static core_channel_t _defaults = {
    LOG_T_INIT_OBJ("core.channel"),
    0, { 0 }, 0
};

core_log_t* core_channel_log()
{
    return &_log;
}

void core_channel_init(core_channel_t* self, size_t size)
{
    mlassert_self();
    if (!(size = (size >> 2) << 2)) {
        mlfatal("invalid size");
    }

    *self = _defaults;

    lfatal_oom(self->ring_buf = malloc(sizeof(ck_ring_buffer_t) * size));
    ck_ring_init(&self->ring, size);
}

void core_channel_destroy(core_channel_t* self)
{
    mlassert_self();
    free(self->ring_buf);
}

void core_channel_put(core_channel_t* self, void* obj)
{
    mlassert_self();
    lassert(self->ring_buf, "ring_buf is nil");
    lassert(obj, "obj is nil");

    while (!ck_ring_enqueue_spsc(&self->ring, self->ring_buf, obj)) {
        sched_yield();
    }
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

void core_channel_close(core_channel_t* self)
{
    mlassert_self();
    ck_pr_store_int(&self->closed, 1);
}

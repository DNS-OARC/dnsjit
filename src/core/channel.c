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

#ifdef HAVE_CK_RING_H
#define __my_USE_CK 1
#include <ck_ring.h>
#include <ck_pr.h>
#else
#ifdef HAVE_CK_CK_RING_H
#define __my_USE_CK 1
#include <ck/ck_ring.h>
#include <ck/ck_pr.h>
#endif
#endif
#ifdef __my_USE_CK
#include <sched.h>
#endif

static core_log_t     _log      = LOG_T_INIT("core.channel");
static core_channel_t _defaults = {
    LOG_T_INIT_OBJ("core.channel"),
    0, 0, 0,
    0, 0,
    0, 0,
    0, 0, 0
};
#ifndef __my_USE_CK
static core_channel_item_t _item_defaults = {
    0,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER, PTHREAD_COND_INITIALIZER,
    0
};
#endif

core_log_t* core_channel_log()
{
    return &_log;
}

int core_channel_init(core_channel_t* self, size_t size)
{
    if (!self || !size) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

#ifdef __my_USE_CK
    size = (size >> 2) << 2;
    if (!size) {
        return 1;
    }
    if (!(self->ring_buf = malloc(sizeof(ck_ring_buffer_t) * size))) {
        return 1;
    }
    if (!(self->ring = malloc(sizeof(ck_ring_t)))) {
        return 1;
    }
    ck_ring_init((ck_ring_t*)self->ring, size);
#else
    self->items = size;
    if (!(self->item = malloc(sizeof(core_channel_item_t) * self->items))) {
        self->items = 0;
        return 1;
    }
    {
        size_t n;
        for (n = 0; n < self->items; n++) {
            self->item[n] = _item_defaults;
        }
    }
#endif

    return 0;
}

int core_channel_destroy(core_channel_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

#ifdef __my_USE_CK
    free(self->ring);
    free(self->ring_buf);
#else
    free(self->item);
#endif

    return 0;
}

int core_channel_put(core_channel_t* self, core_object_t* obj)
{
    if (!self || !obj) {
        return 1;
    }

#ifdef __my_USE_CK
    if (!self->ring_buf || !self->ring) {
        return 1;
    }

    while (!ck_ring_enqueue_spsc((ck_ring_t*)self->ring, (ck_ring_buffer_t*)self->ring_buf, (void*)obj)) {
        sched_yield();
    }
#else
    if (!self->item) {
        return 1;
    }

    {
        core_channel_item_t* item = &self->item[self->at];
        if (pthread_mutex_lock(&item->mutex)) {
            lfatal("mutex lock failed");
        }
        while (item->obj) {
            if (pthread_cond_wait(&item->write, &item->mutex)) {
                lfatal("cond wait failed");
            }
        }
        item->obj = obj;
        if (pthread_cond_signal(&item->read)) {
            lfatal("cond signal failed");
        }
        if (pthread_mutex_unlock(&item->mutex)) {
            lfatal("mutex unlock failed");
        }
    }

    self->at++;
    if (self->at == self->items)
        self->at = 0;
#endif

    return 0;
}

core_object_t* core_channel_get(core_channel_t* self)
{
    core_object_t* obj = 0;

    if (!self) {
        return 0;
    }

#ifdef __my_USE_CK
    if (!self->ring_buf || !self->ring) {
        return 0;
    }

    while (!ck_ring_dequeue_spsc((ck_ring_t*)self->ring, (ck_ring_buffer_t*)self->ring_buf, &obj)) {
        sched_yield();
        if (ck_pr_load_int(&self->ring_closed)) {
            return 0;
        }
    }
#else
    if (!self->item) {
        return 0;
    }

    while (self->read_ends < self->items) {
        core_channel_item_t* item = &self->item[self->read];
        if (pthread_mutex_lock(&item->mutex)) {
            lfatal("mutex lock failed");
        }
        if (!item->end) {
            while (!item->end && !item->obj) {
                if (pthread_cond_wait(&item->read, &item->mutex)) {
                    lfatal("cond wait failed");
                }
            }
        }
        if (item->end) {
            self->read_ends++;
            obj       = item->obj;
            item->obj = 0;
            if (pthread_mutex_unlock(&item->mutex)) {
                lfatal("mutex unlock failed");
            }

            self->read++;
            if (self->read == self->items)
                self->read = 0;

            if (obj)
                break;

            continue;
        }

        obj       = item->obj;
        item->obj = 0;
        if (pthread_cond_signal(&item->write)) {
            lfatal("cond signal failed");
        }
        if (pthread_mutex_unlock(&item->mutex)) {
            lfatal("mutex unlock failed");
        }

        self->read++;
        if (self->read == self->items)
            self->read = 0;

        break;
    }
#endif

    return obj;
}

int core_channel_close(core_channel_t* self)
{
    if (!self) {
        return 1;
    }

#ifdef __my_USE_CK
    ck_pr_store_int(&self->ring_closed, 1);
#else
    if (!self->item) {
        return 1;
    }

    {
        size_t n;
        for (n = 0; n < self->items; n++) {
            core_channel_item_t* item = &self->item[n];
            if (pthread_mutex_lock(&item->mutex)) {
                lfatal("mutex lock failed");
            }
            item->end = 1;
            if (pthread_cond_broadcast(&item->read)) {
                lfatal("cond broadcast failed");
            }
            if (pthread_mutex_unlock(&item->mutex)) {
                lfatal("mutex unlock failed");
            }
        }
    }
#endif

    return 0;
}

int core_channel_run(core_channel_t* self)
{
    core_object_t* obj;

    if (!self || !self->recv) {
        return 1;
    }

    while ((obj = core_channel_get(self))) {
        self->recv(self->ctx, obj);
        // TODO free obj?
    }

    return 0;
}

static int _receive(void* ctx, const core_object_t* obj)
{
    core_channel_t* self = (core_channel_t*)ctx;
    core_object_t*  copy = core_object_copy(obj);

    if (!self || !copy) {
        return 1;
    }

#ifdef __my_USE_CK
    if (!self->ring_buf || !self->ring) {
        return 1;
    }

    while (!ck_ring_enqueue_spsc((ck_ring_t*)self->ring, (ck_ring_buffer_t*)self->ring_buf, &copy)) {
        sched_yield();
    }
#else
    if (!self->item) {
        return 1;
    }

    {
        core_channel_item_t* item = &self->item[self->at];
        if (pthread_mutex_lock(&item->mutex)) {
            lfatal("mutex lock failed");
        }
        while (item->obj) {
            if (pthread_cond_wait(&item->write, &item->mutex)) {
                lfatal("cond wait failed");
            }
        }
        item->obj = copy;
        if (pthread_cond_signal(&item->read)) {
            lfatal("cond signal failed");
        }
        if (pthread_mutex_unlock(&item->mutex)) {
            lfatal("mutex unlock failed");
        }
    }

    self->at++;
    if (self->at == self->items)
        self->at = 0;
#endif

    return 0;
}

core_receiver_t core_channel_receiver()
{
    return _receive;
}

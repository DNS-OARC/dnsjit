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

#include "filter/split.h"
#include "core/assert.h"

static core_log_t     _log      = LOG_T_INIT("filter.split");
static filter_split_t _defaults = {
    LOG_T_INIT_OBJ("filter.split"),
    FILTER_SPLIT_MODE_ROUNDROBIN, 0, 0, 0
};

core_log_t* filter_split_log()
{
    return &_log;
}

void filter_split_init(filter_split_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void filter_split_destroy(filter_split_t* self)
{
    filter_split_recv_t* r;
    mlassert_self();

    if (self->recv_last)
        self->recv_last->next = 0;
    while ((r = self->recv_first)) {
        self->recv_first = r->next;
        free(r);
    }
}

void filter_split_add(filter_split_t* self, core_receiver_t recv, void* ctx)
{
    filter_split_recv_t* r;
    mlassert_self();
    lassert(recv, "recv is nil");

    lfatal_oom(r = malloc(sizeof(filter_split_recv_t)));
    r->recv = recv;
    r->ctx  = ctx;

    if (self->recv_last) {
        self->recv_last->next = r;
        r->next               = self->recv_first;
        self->recv_first      = r;
    } else {
        self->recv_first = self->recv = self->recv_last = r;
        r->next                                         = r;
    }
}

static void _roundrobin(filter_split_t* self, const core_object_t* obj)
{
    mlassert_self();

    self->recv->recv(self->recv->ctx, obj);
    self->recv = self->recv->next;
}

static void _sendall(filter_split_t* self, const core_object_t* obj)
{
    filter_split_recv_t* r;
    mlassert_self();

    for (r = self->recv_first; r; r = r->next) {
        r->recv(r->ctx, obj);
        if (r == self->recv_last)
            break;
    }
}

core_receiver_t filter_split_receiver(filter_split_t* self)
{
    mlassert_self();

    if (!self->recv) {
        lfatal("no receiver(s) set");
    }

    switch (self->mode) {
    case FILTER_SPLIT_MODE_ROUNDROBIN:
        return (core_receiver_t)_roundrobin;
    case FILTER_SPLIT_MODE_SENDALL:
        return (core_receiver_t)_sendall;
    default:
        lfatal("invalid split mode");
    }
    return 0;
}

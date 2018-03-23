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

static core_log_t     _log      = LOG_T_INIT("filter.split");
static filter_split_t _defaults = {
    LOG_T_INIT_OBJ("filter.split"), FILTER_SPLIT_MODE_ROUNDROBIN, 0, 0
};

core_log_t* filter_split_log()
{
    return &_log;
}

int filter_split_init(filter_split_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    return 0;
}

int filter_split_destroy(filter_split_t* self)
{
    filter_split_recv_t* r;
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    while ((r = self->recv_list)) {
        self->recv_list = r->next;
        free(r);
    }

    return 0;
}

int filter_split_add(filter_split_t* self, core_receiver_t recv, void* ctx)
{
    filter_split_recv_t* r;
    if (!self) {
        return 1;
    }

    ldebug("add recv %p obj %p", recv, ctx);

    if (!(r = malloc(sizeof(filter_split_recv_t)))) {
        return 1;
    }

    r->next         = self->recv_list;
    r->recv         = recv;
    r->ctx          = ctx;
    self->recv_list = r;

    if (!self->recv) {
        self->recv = self->recv_list;
    }

    return 0;
}

static int _receive(void* ctx, const core_object_t* obj)
{
    filter_split_t* self = (filter_split_t*)ctx;

    if (!self || !obj || !self->recv) {
        return 1;
    }

    switch (self->mode) {
    case FILTER_SPLIT_MODE_ROUNDROBIN:
        self->recv->recv(self->recv->ctx, obj);
        self->recv = self->recv->next;
        if (!self->recv) {
            self->recv = self->recv_list;
        }
        return 0;
    case FILTER_SPLIT_MODE_SENDALL:
        while (self->recv) {
            self->recv->recv(self->recv->ctx, obj);
            self->recv = self->recv->next;
        }
        self->recv = self->recv_list;
        return 0;
    default:
        break;
    }

    return 1;
}

core_receiver_t filter_split_receiver()
{
    return _receive;
}

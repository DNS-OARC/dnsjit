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

#include "filter/multicopy.h"

static core_log_t         _log      = LOG_T_INIT("filter.multicopy");
static filter_multicopy_t _defaults = {
    LOG_T_INIT_OBJ("filter.multicopy"), 0
};

core_log_t* filter_multicopy_log()
{
    return &_log;
}

int filter_multicopy_init(filter_multicopy_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    return 0;
}

int filter_multicopy_destroy(filter_multicopy_t* self)
{
    filter_multicopy_recv_t* r;
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

int filter_multicopy_add(filter_multicopy_t* self, core_receiver_t recv, void* robj)
{
    filter_multicopy_recv_t* r;
    if (!self) {
        return 1;
    }

    ldebug("add recv %p obj %p", recv, robj);

    if (!(r = malloc(sizeof(filter_multicopy_recv_t)))) {
        return 1;
    }

    r->next         = self->recv_list;
    r->recv         = recv;
    r->robj         = robj;
    self->recv_list = r;

    return 0;
}

static int _receive(void* robj, core_query_t* q)
{
    filter_multicopy_t*      self = (filter_multicopy_t*)robj;
    filter_multicopy_recv_t* r;
    core_query_t*            copy;

    if (!self || !q || !self->recv_list) {
        core_query_free(q);
        return 1;
    }

    for (r = self->recv_list; r; r = r->next) {
        if ((copy = core_query_copy(q))) {
            r->recv(r->robj, copy);
        }
    }
    core_query_free(q);

    return 0;
}

core_receiver_t filter_multicopy_receiver()
{
    return _receive;
}

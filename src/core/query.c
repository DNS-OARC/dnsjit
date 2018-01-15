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

#include "core/query.h"

#include <string.h>

static query_t _defaults = {
    LOG_T_INIT,
    0, 0, 0, 0, 0, 0, 0,
    0, { 0, 0 },
    "", 0, 0
};

query_t* query_new()
{
    query_t* self = calloc(1, sizeof(query_t));

    ldebug("new %p", self);

    *self          = _defaults;
    self->_alloced = 1;

    return self;
}

void query_free(query_t* self)
{
    ldebug("free %p", self);

    if (self && self->_alloced) {
        free(self->raw);
        free(self);
    }
}

int query_init(query_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("init %p", self);

    *self = _defaults;

    return 0;
}

int query_destroy(query_t* self)
{
    if (!self || self->_alloced) {
        return 1;
    }

    ldebug("destroy %p", self);

    free(self->raw);

    return 0;
}

int query_set_raw(query_t* self, const char* raw, size_t len)
{
    if (!self || !raw || !len) {
        return 1;
    }

    ldebug("set raw %p %p %lu", self, raw, len);

    if (self->raw) {
        free(self->raw);
        self->raw      = 0;
        self->len      = 0;
        self->have_raw = 0;
    }
    if (len > sizeof(self->small)) {
        if (!(self->raw = calloc(1, len))) {
            return 1;
        }
        memcpy(self->raw, raw, len);
    } else {
        memcpy(self->small, raw, len);
    }
    self->len      = len;
    self->have_raw = 1;

    return 0;
}

query_t* query_copy(query_t* self)
{
    query_t* q = query_new();

    ldebug("copy %p -> %p", self, q);

    if (q) {
        q->is_udp = self->is_udp;
        q->is_tcp = self->is_tcp;
        if (self->have_raw) {
            query_set_raw(q, self->raw ? self->raw : self->small, self->len);
        }
    }

    return q;
}

#define assert(a...)

inline int query_is_udp(const query_t* query)
{
    assert(query);
    return query->is_udp;
}

inline int query_is_tcp(const query_t* query)
{
    assert(query);
    return query->is_tcp;
}

inline int query_have_ipv4(const query_t* query)
{
    assert(query);
    return query->have_ipv4;
}

inline int query_have_ipv6(const query_t* query)
{
    assert(query);
    return query->have_ipv6;
}

inline int query_have_port(const query_t* query)
{
    assert(query);
    return query->have_port;
}

inline int query_have_raw(const query_t* query)
{
    assert(query);
    return query->have_raw;
}

inline size_t query_length(const query_t* query)
{
    assert(query);
    return query->len;
}

inline const u_char* query_raw(const query_t* query)
{
    assert(query);
    return query->raw ? (u_char*)query->raw : (u_char*)query->small;
}

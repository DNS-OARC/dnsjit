/*
 * Copyright (c) 2019, CZ.NIC, z.s.p.o.
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

#include "filter/copy.h"
#include "core/assert.h"

static core_log_t _log = LOG_T_INIT("filter.copy");
static filter_copy_t _defaults = {
    LOG_T_INIT_OBJ("filter.copy"),
    0, 0,
    0
};

core_log_t* filter_copy_log()
{
    return &_log;
}

void filter_copy_init(filter_copy_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void filter_copy_destroy(filter_copy_t* self)
{
    mlassert_self();
}

void filter_copy_set(filter_copy_t* self, int32_t obj_type)
{
    mlassert_self();

    switch (obj_type) {
    case CORE_OBJECT_NONE:
        self->copy |= 0x1;
        break;
    case CORE_OBJECT_PCAP:
        self->copy |= 0x2;
        break;
    case CORE_OBJECT_ETHER:
        self->copy |= 0x4;
        break;
    case CORE_OBJECT_NULL:
        self->copy |= 0x8;
        break;
    case CORE_OBJECT_LOOP:
        self->copy |= 0x10;
        break;
    case CORE_OBJECT_LINUXSLL:
        self->copy |= 0x20;
        break;
    case CORE_OBJECT_IEEE802:
        self->copy |= 0x40;
        break;
    case CORE_OBJECT_GRE:
        self->copy |= 0x80;
        break;
    case CORE_OBJECT_IP:
        self->copy |= 0x100;
        break;
    case CORE_OBJECT_IP6:
        self->copy |= 0x200;
        break;
    case CORE_OBJECT_ICMP:
        self->copy |= 0x400;
        break;
    case CORE_OBJECT_ICMP6:
        self->copy |= 0x800;
        break;
    case CORE_OBJECT_UDP:
        self->copy |= 0x1000;
        break;
    case CORE_OBJECT_TCP:
        self->copy |= 0x2000;
        break;
    case CORE_OBJECT_PAYLOAD:
        self->copy |= 0x4000;
        break;
    case CORE_OBJECT_DNS:
        self->copy |= 0x8000;
        break;
    default:
        lfatal("unknown type %d", obj_type);
    }
}

uint64_t filter_copy_get(filter_copy_t* self, int32_t obj_type)
{
    mlassert_self();

    switch (obj_type) {
    case CORE_OBJECT_NONE:
        return self->copy & 0x1;
    case CORE_OBJECT_PCAP:
        return self->copy & 0x2;
    case CORE_OBJECT_ETHER:
        return self->copy & 0x4;
    case CORE_OBJECT_NULL:
        return self->copy & 0x8;
    case CORE_OBJECT_LOOP:
        return self->copy & 0x10;
    case CORE_OBJECT_LINUXSLL:
        return self->copy & 0x20;
    case CORE_OBJECT_IEEE802:
        return self->copy & 0x40;
    case CORE_OBJECT_GRE:
        return self->copy & 0x80;
    case CORE_OBJECT_IP:
        return self->copy & 0x100;
    case CORE_OBJECT_IP6:
        return self->copy & 0x200;
    case CORE_OBJECT_ICMP:
        return self->copy & 0x400;
    case CORE_OBJECT_ICMP6:
        return self->copy & 0x800;
    case CORE_OBJECT_UDP:
        return self->copy & 0x1000;
    case CORE_OBJECT_TCP:
        return self->copy & 0x2000;
    case CORE_OBJECT_PAYLOAD:
        return self->copy & 0x4000;
    case CORE_OBJECT_DNS:
        return self->copy & 0x8000;
    default:
        lfatal("unknown type %d", obj_type);
    }
}

static void _receive(filter_copy_t* self, const core_object_t* obj)
{
    mlassert_self();
    lassert(obj, "obj is nil");

    core_object_t* first = NULL;
    core_object_t* parent = NULL;
    core_object_t* current = NULL;
    const core_object_t* srcobj = obj;

    do {
        if (filter_copy_get(self, srcobj->obj_type)) {
            parent = current;
            current = core_object_copy(srcobj);
            if (parent == NULL) {
                parent = current;
                first = current;
            } else {
                parent->obj_prev = current;
            }
        }
        srcobj = srcobj->obj_prev;
    } while(srcobj != NULL);

    if (first == NULL) {
        lnotice("object discarded (no types to copy)");
        return;
    }

    self->recv(self->recv_ctx, first);
}

core_receiver_t filter_copy_receiver(filter_copy_t* self)
{
    mlassert_self();

    if (!self->recv) {
        lfatal("no receiver(s) set");
    }

    return (core_receiver_t)_receive;
}

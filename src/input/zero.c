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

#include "input/zero.h"
#include "core/object/packet.h"

#include <time.h>

static core_log_t   _log      = LOG_T_INIT("input.zero");
static input_zero_t _defaults = {
    LOG_T_INIT_OBJ("input.zero"),
    0, 0,
    0
};

static core_object_packet_t _pkt        = CORE_OBJECT_PACKET_INIT(0);
static core_object_packet_t _shared_pkt = CORE_OBJECT_PACKET_INIT(0);

static void _ref(core_object_t* obj, core_object_reference_t ref)
{
}

core_log_t* input_zero_log()
{
    return &_log;
}

int input_zero_init(input_zero_t* self)
{
    if (!self) {
        return 1;
    }

    *self               = _defaults;
    _shared_pkt.obj_ref = _ref;

    ldebug("init");

    return 0;
}

int input_zero_destroy(input_zero_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    return 0;
}

int input_zero_run(input_zero_t* self, uint64_t num)
{
    core_object_t*  obj;
    core_receiver_t r;
    void*           c;

    if (!self || !self->recv) {
        return 1;
    }

    ldebug("run");

    if (self->use_shared) {
        obj = (core_object_t*)&_shared_pkt;
    } else {
        obj = (core_object_t*)&_pkt;
    }

    r = self->recv;
    c = self->ctx;
    while (num--) {
        r(c, obj);
    }

    return 0;
}

static const core_object_t* _produce(void* ctx)
{
    return (core_object_t*)&_pkt;
}

static const core_object_t* _produce_shared(void* ctx)
{
    return (core_object_t*)&_shared_pkt;
}

core_producer_t input_zero_producer(input_zero_t* self)
{
    if (self && self->use_shared) {
        return _produce_shared;
    }
    return _produce;
}

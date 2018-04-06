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
    { 0, 0 }, { 0, 0 },
    0
};

core_log_t* input_zero_log()
{
    return &_log;
}

int input_zero_init(input_zero_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

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

static core_object_packet_t shared_pkt = CORE_OBJECT_PACKET_INIT(0);

static void _ref(core_object_t* obj, core_object_reference_t ref)
{
}

int input_zero_run(input_zero_t* self, uint64_t num)
{
    struct timespec      ts, te;
    core_object_packet_t pkt = CORE_OBJECT_PACKET_INIT(0);
    core_object_t*       obj = (core_object_t*)&pkt;

    if (!self || !self->recv) {
        return 1;
    }

    ldebug("run");

    if (self->use_shared) {
        shared_pkt.obj_ref = _ref;
        obj                = (core_object_t*)&shared_pkt;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts);
    while (num--) {
        self->recv(self->ctx, obj);
    }
    clock_gettime(CLOCK_MONOTONIC, &te);

    self->ts.sec  = ts.tv_sec;
    self->ts.nsec = ts.tv_nsec;
    self->te.sec  = te.tv_sec;
    self->te.nsec = te.tv_nsec;

    return 0;
}

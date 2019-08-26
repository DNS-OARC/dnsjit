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

#include "output/dnssim.h"
#include "core/assert.h"
#include "core/object/pcap.h"

static core_log_t _log = LOG_T_INIT("output.dnssim");
static output_dnssim_t _defaults = {
    LOG_T_INIT_OBJ("output.dnssim"),
    OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY, 0
};

core_log_t* output_dnssim_log()
{
    return &_log;
}

void output_dnssim_init(output_dnssim_t* self)
{
    mlassert_self();

    *self = _defaults;

    if (!uv_loop_init(&self->loop)) {
        // TODO log errno
        lfatal("failed to initialize uv_loop");
    }
    ldebug("initialized uv_loop");
}

void output_dnssim_destroy(output_dnssim_t* self)
{
    mlassert_self();

    if (!uv_loop_close(&self->loop)) {
        // TODO log errno
        lcritical("failed to close uv_loop");
    } else {
        ldebug("closed uv_loop");
    }
}

static void _receive(output_dnssim_t* self, const core_object_t* obj)
{
    mlassert_self();
}

core_receiver_t output_dnssim_receiver()
{
    return (core_receiver_t)_receive;
}

int output_dnssim_run_nowait(output_dnssim_t* self)
{
    mlassert_self();

    return uv_run(&self->loop, UV_RUN_NOWAIT);
}

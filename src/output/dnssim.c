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

typedef struct _output_dnssim {
    output_dnssim_t pub;

    uv_loop_t loop;
    ck_ring_buffer_t* ring_buf;  /* ring buffer for data from receive() */
    ck_ring_t ring;
} _output_dnssim_t;

static core_log_t _log = LOG_T_INIT("output.dnssim");
static output_dnssim_t _defaults = {
    LOG_T_INIT_OBJ("output.dnssim"),
    OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY, 0, 0
};

core_log_t* output_dnssim_log()
{
    return &_log;
}

#define _self ((_output_dnssim_t*)self)
#define RING_BUF_SIZE 8192

output_dnssim_t* output_dnssim_new()
{
    output_dnssim_t* self;
    int ret;

    mlfatal_oom(self = malloc(sizeof(_output_dnssim_t)));
    lfatal_oom(_self->ring_buf = calloc(
        RING_BUF_SIZE, sizeof(ck_ring_buffer_t)));
    *self = _defaults;

    ck_ring_init(&_self->ring, RING_BUF_SIZE);

    ret = uv_loop_init(&_self->loop);
    if (ret < 0) {
        lfatal("failed to initialize uv_loop (%s)", uv_strerror(ret));
    }
    ldebug("initialized uv_loop");

    return self;
}

void output_dnssim_free(output_dnssim_t* self)
{
    mlassert_self();
    int ret;

    free(_self->ring_buf);

    ret = uv_loop_close(&_self->loop);
    if (ret < 0) {
        lcritical("failed to close uv_loop (%s)", uv_strerror(ret));
    } else {
        ldebug("closed uv_loop");
    }

    free(self);
}

static void _receive(output_dnssim_t* self, const core_object_t* obj)
{
    mlassert_self();

    if (!ck_ring_enqueue_spsc(&_self->ring, _self->ring_buf, (void*)obj)) {
        self->dropped_pkts++;
        if (self->dropped_pkts == 1) {
            lcritical("buffer full, dropping packet(s)");
        }
    }
}

core_receiver_t output_dnssim_receiver()
{
    return (core_receiver_t)_receive;
}

int output_dnssim_run_nowait(output_dnssim_t* self)
{
    mlassert_self();
    void *obj;

    /* retrieve packets from buffer */
    while(ck_ring_dequeue_spsc(&_self->ring, _self->ring_buf, &obj) == true) {
        switch(((core_object_t*)obj)->obj_type) {
        case CORE_OBJECT_IP:
        case CORE_OBJECT_IP6:
            // TODO send
            break;
        default:
            self->invalid_pkts++;
            if (self->invalid_pkts == 1) {
                lcritical("input packets must be either IP or IP6");
            }
            break;
        }
    }

    return uv_run(&_self->loop, UV_RUN_NOWAIT);
}

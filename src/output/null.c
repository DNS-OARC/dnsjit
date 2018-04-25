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

#include "output/null.h"
#include "core/object/pcap.h"

static core_log_t    _log      = LOG_T_INIT("output.null");
static output_null_t _defaults = {
    LOG_T_INIT_OBJ("output.null"),
    0, 0, 0
};

core_log_t* output_null_log()
{
    return &_log;
}

int output_null_init(output_null_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    return 0;
}

int output_null_destroy(output_null_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    return 0;
}

static int _receive(void* ctx, const core_object_t* obj)
{
    output_null_t* self = (output_null_t*)ctx;

    if (self) {
        if (obj && obj->obj_type == CORE_OBJECT_PCAP) {
            const core_object_pcap_t* pkt = (core_object_pcap_t*)obj;
            if (pkt->is_multiple) {
                while (pkt) {
                    self->pkts++;
                    pkt = (core_object_pcap_t*)pkt->obj_prev;
                }
                return 0;
            }
        }
        self->pkts++;
    }

    return 0;
}

core_receiver_t output_null_receiver()
{
    return _receive;
}

int output_null_run(output_null_t* self, uint64_t num)
{
    core_producer_t p;
    void*           c;

    if (!self || !self->prod) {
        return 1;
    }

    ldebug("run");

    p = self->prod;
    c = self->ctx;
    while (num--) {
        const core_object_t* obj = p(c);
        if (obj) {
            if (obj->obj_type == CORE_OBJECT_PCAP) {
                const core_object_pcap_t* pkt = (core_object_pcap_t*)obj;
                if (pkt->is_multiple) {
                    while (pkt) {
                        self->pkts++;
                        pkt = (core_object_pcap_t*)pkt->obj_prev;
                    }
                    continue;
                }
            }
            self->pkts++;
        }
    }

    return 0;
}

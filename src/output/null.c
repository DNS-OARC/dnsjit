/*
 * Copyright (c) 2018-2021, OARC, Inc.
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
#include "core/assert.h"
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

void output_null_init(output_null_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void output_null_destroy(output_null_t* self)
{
    mlassert_self();
}

static void _receive(output_null_t* self, const core_object_t* obj)
{
    mlassert_self();

    self->pkts++;
}

core_receiver_t output_null_receiver()
{
    return (core_receiver_t)_receive;
}

void output_null_run(output_null_t* self, int64_t num)
{
    mlassert_self();

    if (!self->prod) {
        lfatal("no producer set");
    }

    if (num > 0) {
        while (num--) {
            const core_object_t* obj = self->prod(self->ctx);
            if (!obj)
                break;

            self->pkts++;
        }
    } else {
        for (;;) {
            const core_object_t* obj = self->prod(self->ctx);
            if (!obj)
                break;

            self->pkts++;
        }
    }
}

/*
 * Copyright (c) 2018-2019, OARC, Inc.
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
#include "core/assert.h"
#include "core/object/null.h"

#include <time.h>

static core_log_t   _log      = LOG_T_INIT("input.zero");
static input_zero_t _defaults = {
    LOG_T_INIT_OBJ("input.zero"),
    0, 0,
};

static core_object_null_t _null = CORE_OBJECT_NULL_INIT(0);

core_log_t* input_zero_log()
{
    return &_log;
}

void input_zero_init(input_zero_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void input_zero_destroy(input_zero_t* self)
{
    mlassert_self();
}

void input_zero_run(input_zero_t* self, uint64_t num)
{
    mlassert_self();
    if (!self->recv) {
        lfatal("no receiver set");
    }

    while (num--) {
        self->recv(self->ctx, (core_object_t*)&_null);
    }
}

static const core_object_t* _produce(void* ctx)
{
    return (core_object_t*)&_null;
}

core_producer_t input_zero_producer()
{
    return _produce;
}

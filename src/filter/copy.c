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

    lfatal_oom(self->copy = calloc(CORE_OBJECT_DNS + 1, sizeof(uint8_t)));
}

void filter_copy_destroy(filter_copy_t* self)
{
    mlassert_self();

    free(self->copy);
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
        lassert(srcobj->obj_type >= CORE_OBJECT_NONE && srcobj->obj_type <= CORE_OBJECT_DNS,
            "invalid object type");
        if (self->copy[srcobj->obj_type]) {
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
        lnotice("packet discarded (no layers copied)");
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

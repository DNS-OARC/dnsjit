/*
 * Copyright (c) 2018-2025 OARC, Inc.
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

#include "core/object/pcap.h"
#include "core/assert.h"

#include <stdlib.h>
#include <string.h>

core_object_pcap_t* core_object_pcap_copy(const core_object_pcap_t* self)
{
    core_object_pcap_t* copy;
    glassert_self();

    glfatal_oom(copy = malloc(sizeof(core_object_pcap_t) + self->caplen));
    memcpy(copy, self, sizeof(core_object_pcap_t));
    copy->obj_prev = 0;

    if (copy->bytes) {
        copy->bytes = (void*)copy + sizeof(core_object_pcap_t);
        memcpy((void*)copy->bytes, self->bytes, self->caplen);
    }

    return copy;
}

void core_object_pcap_free(core_object_pcap_t* self)
{
    glassert_self();
    free(self);
}

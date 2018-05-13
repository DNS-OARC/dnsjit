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

#include "core/object.h"
#include "core/object/pcap.h"
#include "core/object/udp.h"

#include <stdlib.h>
#include <string.h>

/* TODO: document */
core_object_t* core_object_copy(const core_object_t* obj)
{
    if (!obj) {
        return 0;
    }

    if (obj->obj_ref) {
        obj->obj_ref((core_object_t*)obj, CORE_OBJECT_INCREF);
        return (core_object_t*)obj;
    }

    switch (obj->obj_type) {
    case CORE_OBJECT_PCAP: {
        core_object_pcap_t* pcap = (core_object_pcap_t*)obj;
        core_object_pcap_t* copy = malloc(sizeof(core_object_pcap_t) + pcap->caplen);

        if (!copy) {
            return 0;
        }

        memcpy(copy, pcap, sizeof(core_object_pcap_t));
        copy->obj_prev = 0;

        memcpy((void*)copy + sizeof(core_object_pcap_t), pcap->bytes, pcap->caplen);
        copy->bytes = (unsigned char*)copy + sizeof(core_object_pcap_t);

        return (core_object_t*)copy;
    }
    // case CORE_OBJECT_UDP: {
    //     core_object_udp_t* udp  = (core_object_udp_t*)obj;
    //     core_object_udp_t* copy = malloc(sizeof(core_object_udp_t) + udp->len);
    //
    //     memcpy(copy, udp, sizeof(core_object_udp_t));
    //     copy->obj_prev = 0;
    //
    //     memcpy((void*)copy + sizeof(core_object_udp_t), udp->payload, udp->len);
    //     copy->payload = (unsigned char*)copy + sizeof(core_object_udp_t);
    //
    //     return (core_object_t*)copy;
    // }
    default:
        break;
    }

    return 0;
}

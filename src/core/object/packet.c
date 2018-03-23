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

#include "core/object/packet.h"

#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>

char* _ntop(core_object_packet_t* self, const void* addr)
{
    char* buf;

    if (self->is_ipv6) {
        if (!(buf = malloc(INET6_ADDRSTRLEN))) {
            return 0;
        }
        if (!inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN)) {
            free(buf);
            return 0;
        }
    } else {
        if (!(buf = malloc(INET_ADDRSTRLEN))) {
            return 0;
        }
        if (!inet_ntop(AF_INET, addr, buf, INET_ADDRSTRLEN)) {
            free(buf);
            return 0;
        }
    }

    return buf;
}

char* core_object_packet_src(core_object_packet_t* self)
{
    if (!self || !self->src_addr) {
        return 0;
    }

    return _ntop(self, self->src_addr);
}

char* core_object_packet_dst(core_object_packet_t* self)
{
    if (!self || !self->dst_addr) {
        return 0;
    }

    return _ntop(self, self->dst_addr);
}

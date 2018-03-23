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

//lua:require("dnsjit.core.object_h")
//lua:require("dnsjit.core.timespec_h")

typedef struct core_object_packet {
    unsigned short       obj_type;
    const core_object_t* obj_prev;

    uint64_t src_id, qr_id, dst_id;

    unsigned short is_udp : 1;
    unsigned short is_tcp : 1;
    unsigned short is_ipv6 : 1;

    const void* src_addr;
    const void* dst_addr;

    uint16_t        sport, dport;
    core_timespec_t ts;

    const uint8_t* payload;
    size_t         len;
} core_object_packet_t;

char* core_object_packet_src(core_object_packet_t* self);
char* core_object_packet_dst(core_object_packet_t* self);

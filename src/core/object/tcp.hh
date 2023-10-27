/*
 * Copyright (c) 2018-2024 OARC, Inc.
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

// lua:require("dnsjit.core.object_h")

typedef struct core_object_tcp {
    const core_object_t* obj_prev;
    int32_t              obj_type;

    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off : 4;
    uint8_t  x2 : 4;
    uint8_t  flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;

    uint8_t opts[64];
    size_t  opts_len;
} core_object_tcp_t;

core_object_tcp_t* core_object_tcp_copy(const core_object_tcp_t* self);
void               core_object_tcp_free(core_object_tcp_t* self);

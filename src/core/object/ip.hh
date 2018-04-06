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

typedef struct core_object_ip {
    unsigned short        obj_type;
    const core_object_t*  obj_prev;
    core_object_refcall_t obj_ref;
    void*                 obj_refctx;

    unsigned int v : 4;
    unsigned int hl : 4;
    uint8_t      tos;
    uint16_t     len;
    uint16_t     id;
    uint16_t     off;
    uint8_t      ttl;
    uint8_t      p;
    uint16_t     sum;
    uint8_t      src[4], dst[4];

    const uint8_t* payload;
    size_t         plen;
} core_object_ip_t;

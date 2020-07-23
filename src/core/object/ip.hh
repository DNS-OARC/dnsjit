/*
 * Copyright (c) 2018-2020, OARC, Inc.
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
    const core_object_t* obj_prev;
    int32_t              obj_type;

    uint8_t  v;
    uint8_t  hl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t  ttl;
    uint8_t  p;
    uint16_t sum;
    uint8_t  src[4], dst[4];
} core_object_ip_t;

core_object_ip_t* core_object_ip_copy(const core_object_ip_t* self);
void              core_object_ip_free(core_object_ip_t* self);

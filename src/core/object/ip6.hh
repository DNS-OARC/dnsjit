/*
 * Copyright (c) 2018-2022, OARC, Inc.
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

typedef struct core_object_ip6 {
    const core_object_t* obj_prev;
    int32_t              obj_type;

    uint32_t flow;
    uint16_t plen;
    uint8_t  nxt;
    uint8_t  hlim;
    uint8_t  src[16];
    uint8_t  dst[16];

    uint8_t  is_frag;
    uint8_t  have_rtdst;
    uint16_t frag_offlg;
    uint16_t frag_ident;
    uint8_t  rtdst[16];
} core_object_ip6_t;

core_object_ip6_t* core_object_ip6_copy(const core_object_ip6_t* self);
void               core_object_ip6_free(core_object_ip6_t* self);

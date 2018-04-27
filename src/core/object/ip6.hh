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

typedef struct core_object_ip6 {
    unsigned short        obj_type;
    const core_object_t*  obj_prev;
    core_object_refcall_t obj_ref;
    void*                 obj_refctx;

    uint32_t flow;
    uint16_t plen;
    uint8_t  nxt;
    uint8_t  hlim;
    uint8_t  src[16];
    uint8_t  dst[16];

    unsigned short is_frag : 1;
    unsigned short have_rtdst : 1;
    uint16_t       frag_offlg;
    uint16_t       frag_ident;
    uint8_t        rtdst[16];

    const uint8_t* payload;
    size_t         len;
    size_t         pad_len;
} core_object_ip6_t;

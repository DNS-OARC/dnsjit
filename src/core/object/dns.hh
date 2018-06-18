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

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.object_h")

typedef struct core_object_dns {
    const core_object_t* obj_prev;
    int32_t              obj_type;

    unsigned short have_id : 1;
    unsigned short have_qr : 1;
    unsigned short have_opcode : 1;
    unsigned short have_aa : 1;
    unsigned short have_tc : 1;
    unsigned short have_rd : 1;
    unsigned short have_ra : 1;
    unsigned short have_z : 1;
    unsigned short have_ad : 1;
    unsigned short have_cd : 1;
    unsigned short have_rcode : 1;
    unsigned short have_qdcount : 1;
    unsigned short have_ancount : 1;
    unsigned short have_nscount : 1;
    unsigned short have_arcount : 1;

    uint16_t       id;
    unsigned short qr : 1;
    unsigned short opcode : 4;
    unsigned short aa : 1;
    unsigned short tc : 1;
    unsigned short rd : 1;
    unsigned short ra : 1;
    unsigned short z : 1;
    unsigned short ad : 1;
    unsigned short cd : 1;
    unsigned short rcode : 4;
    uint16_t       qdcount;
    uint16_t       ancount;
    uint16_t       nscount;
    uint16_t       arcount;

    size_t questions;
    size_t answers;
    size_t authorities;
    size_t additionals;
} core_object_dns_t;

core_log_t* core_object_dns_log();

core_object_dns_t* core_object_dns_new(const core_object_t* obj);
core_object_dns_t* core_object_dns_copy(const core_object_dns_t* self);
void core_object_dns_free(core_object_dns_t* self);

int core_object_dns_parse_header(core_object_dns_t* self);
int core_object_dns_parse(core_object_dns_t* self);

int core_object_dns_rr_reset(core_object_dns_t* self);
int core_object_dns_rr_next(core_object_dns_t* self);
int core_object_dns_rr_ok(core_object_dns_t* self);
const char* core_object_dns_rr_label(core_object_dns_t* self);
uint16_t core_object_dns_rr_type(core_object_dns_t* self);
uint16_t core_object_dns_rr_class(core_object_dns_t* self);
uint32_t core_object_dns_rr_ttl(core_object_dns_t* self);

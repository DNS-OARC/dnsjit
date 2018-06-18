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

typedef struct core_object_dns_label {
    unsigned short is_end : 1;
    unsigned short have_length : 1;
    unsigned short have_offset : 1;
    unsigned short have_extension_bits : 1;
    unsigned short have_dn : 1;
    unsigned short extension_bits : 2;

    uint8_t  length;
    uint16_t offset;
} core_object_dns_label_t;

typedef struct core_object_dns_rr {
    unsigned short have_type : 1;
    unsigned short have_class : 1;
    unsigned short have_ttl : 1;
    unsigned short have_rdlength : 1;
    unsigned short have_rdata : 1;
    unsigned short have_rdata_labels : 1;
    unsigned short have_padding : 1;

    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;

    size_t labels;
    size_t rdata_offset;
    size_t rdata_labels;
    size_t padding_offset;
    size_t padding_length;
} core_object_dns_rr_t;

typedef struct core_object_dns_q {
    unsigned short have_type : 1;
    unsigned short have_class : 1;

    uint16_t type;
    uint16_t class;

    size_t labels;
} core_object_dns_q_t;

typedef struct core_object_dns {
    const core_object_t* obj_prev;
    int32_t              obj_type;

    const uint8_t *payload, *at;
    size_t         len, left;

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
} core_object_dns_t;

core_log_t* core_object_dns_log();

core_object_dns_t* core_object_dns_new();
core_object_dns_t* core_object_dns_copy(const core_object_dns_t* self);
void core_object_dns_free(core_object_dns_t* self);
void core_object_dns_reset(core_object_dns_t* self, const core_object_t* obj);

int core_object_dns_parse_header(core_object_dns_t* self);
int core_object_dns_parse_q(core_object_dns_t* self, core_object_dns_q_t* q, core_object_dns_label_t* label, size_t labels);
int core_object_dns_parse_rr(core_object_dns_t* self, core_object_dns_rr_t* rr, core_object_dns_label_t* label, size_t labels);

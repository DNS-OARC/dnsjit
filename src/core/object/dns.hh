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
    uint8_t is_end;
    uint8_t have_length;
    uint8_t have_offset;
    uint8_t have_extension_bits;
    uint8_t have_dn;
    uint8_t extension_bits;

    uint8_t  length;
    uint16_t offset;
} core_object_dns_label_t;

typedef struct core_object_dns_rr {
    uint8_t have_type;
    uint8_t have_class;
    uint8_t have_ttl;
    uint8_t have_rdlength;
    uint8_t have_rdata;
    uint8_t have_rdata_labels;
    uint8_t have_padding;

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
    uint8_t have_type;
    uint8_t have_class;

    uint16_t type;
    uint16_t class;

    size_t labels;
} core_object_dns_q_t;

typedef struct core_object_dns {
    const core_object_t* obj_prev;
    int32_t              obj_type;

    const uint8_t *payload, *at;
    size_t         len, left;

    uint8_t have_id;
    uint8_t have_qr;
    uint8_t have_opcode;
    uint8_t have_aa;
    uint8_t have_tc;
    uint8_t have_rd;
    uint8_t have_ra;
    uint8_t have_z;
    uint8_t have_ad;
    uint8_t have_cd;
    uint8_t have_rcode;
    uint8_t have_qdcount;
    uint8_t have_ancount;
    uint8_t have_nscount;
    uint8_t have_arcount;

    uint16_t id;
    int8_t   qr;
    uint8_t  opcode;
    uint8_t  aa;
    uint8_t  tc;
    uint8_t  rd;
    uint8_t  ra;
    uint8_t  z;
    uint8_t  ad;
    uint8_t  cd;
    uint8_t  rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} core_object_dns_t;

core_log_t* core_object_dns_log();

core_object_dns_t* core_object_dns_new();
core_object_dns_t* core_object_dns_copy(const core_object_dns_t* self);
void core_object_dns_free(core_object_dns_t* self);
void core_object_dns_reset(core_object_dns_t* self, const core_object_t* obj);

int core_object_dns_parse_header(core_object_dns_t* self);
int core_object_dns_parse_q(core_object_dns_t* self, core_object_dns_q_t* q, core_object_dns_label_t* label, size_t labels);
int core_object_dns_parse_rr(core_object_dns_t* self, core_object_dns_rr_t* rr, core_object_dns_label_t* label, size_t labels);

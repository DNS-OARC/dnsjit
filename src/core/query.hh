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
//lua:require("dnsjit.core.timespec_h")
typedef struct query {
    log_t _log;

    uint64_t sid, qid;

    unsigned short is_udp : 1;
    unsigned short is_tcp : 1;
    unsigned short is_ipv6 : 1;
    unsigned short have_raw : 1;

    uint16_t   sport, dport;
    timespec_t ts;

    char   small[64];
    char*  raw;
    size_t len;

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
} query_t;

log_t*   query_log();
query_t* query_new();
void query_free(query_t* self);
int query_init(query_t* self);
int query_destroy(query_t* self);
int query_set_raw(query_t* self, const char* raw, size_t len);
query_t* query_copy(query_t* self);
const char* query_src(query_t* self);
const char* query_dst(query_t* self);
int query_parse_header(query_t* self);
int query_parse(query_t* self);
int query_rr_next(query_t* self);
int query_rr_ok(query_t* self);
const char* query_rr_label(query_t* self);
uint16_t query_rr_type(query_t* self);
uint16_t query_rr_class(query_t* self);
uint32_t query_rr_ttl(query_t* self);

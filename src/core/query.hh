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

// struct in_addr {};
// struct in6_addr {};
//lua:require("dnsjit.core.log_h")
//lua:require("dnsjit.core.timespec_h")
typedef struct query {
    log_t          log;
    unsigned short _alloced : 1;
    unsigned short is_udp : 1;
    unsigned short is_tcp : 1;
    unsigned short have_ipv4 : 1;
    unsigned short have_ipv6 : 1;
    unsigned short have_port : 1;
    unsigned short have_raw : 1;

    // union {
    // struct in_addr  ip_dst;
    // struct in6_addr ip6_dst;
    // } addr;
    uint16_t   port;
    timespec_t ts;

    char   small[64];
    char*  raw;
    size_t len;
} query_t;

query_t* query_new();
void query_free(query_t* self);
int query_init(query_t* self);
int query_destroy(query_t* self);
int query_set_raw(query_t* self, const char* raw, size_t len);
query_t* query_copy(query_t* self);

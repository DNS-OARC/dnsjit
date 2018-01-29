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

#include "config.h"

#include "core/query.h"

#include <string.h>
#include <arpa/inet.h>

#if INET_ADDRSTRLEN > INET6_ADDRSTRLEN
#define NTOP_BUFSIZE INET_ADDRSTRLEN
#else
#define NTOP_BUFSIZE INET6_ADDRSTRLEN
#endif

typedef struct _query {
    query_t pub;

    int                     af;
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    char                    ntop_buf[NTOP_BUFSIZE];

    omg_dns_t dns;
} _query_t;

static query_t _defaults = {
    LOG_T_INIT,
    0, 0, 0, 0,
    0, { 0, 0 },
    "", 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
static omg_dns_t _omg_dns_defaults = OMG_DNS_T_INIT;

query_t* query_new()
{
    query_t* self = malloc(sizeof(_query_t));
    _query_t* _self = (_query_t*)self;

    ldebug("new %p", self);

    *self = _defaults;
    _self->af = AF_UNSPEC;
    _self->dns = _omg_dns_defaults;

    return self;
}

void query_free(query_t* self)
{
    ldebug("free %p", self);

    if (self) {
        free(self->raw);
        free(self);
    }
}

int query_set_raw(query_t* self, const char* raw, size_t len)
{
    if (!self || !raw || !len) {
        return 1;
    }

    ldebug("set raw %p %p %lu", self, raw, len);

    if (self->raw) {
        free(self->raw);
        self->raw      = 0;
        self->len      = 0;
        self->have_raw = 0;
    }
    if (len > sizeof(self->small)) {
        if (!(self->raw = malloc(len))) {
            return 1;
        }
        memcpy(self->raw, raw, len);
    } else {
        memcpy(self->small, raw, len);
    }
    self->len      = len;
    self->have_raw = 1;

    return 0;
}

query_t* query_copy(query_t* self)
{
    query_t* q = query_new();

    ldebug("copy %p -> %p", self, q);

    if (q) {
        *((_query_t*)q) = *((_query_t*)self);
        q->have_raw     = 0;
        q->raw          = 0;
        q->len          = 0;

        if (self->have_raw) {
            query_set_raw(q, self->raw ? self->raw : self->small, self->len);
        }
    }

    return q;
}

int query_parse_header(query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !self->have_raw || _self->dns.have_header) {
        return 1;
    }

    if (omg_dns_parse_header(&_self->dns, (const u_char*)(self->raw ? self->raw : self->small), self->len)) {
        return 2;
    }

    self->have_id = _self->dns.have_id;
    self->have_qr = _self->dns.have_qr;
    self->have_opcode = _self->dns.have_opcode;
    self->have_aa = _self->dns.have_aa;
    self->have_tc = _self->dns.have_tc;
    self->have_rd = _self->dns.have_rd;
    self->have_ra = _self->dns.have_ra;
    self->have_z = _self->dns.have_z;
    self->have_ad = _self->dns.have_ad;
    self->have_cd = _self->dns.have_cd;
    self->have_rcode = _self->dns.have_rcode;
    self->have_qdcount = _self->dns.have_qdcount;
    self->have_ancount = _self->dns.have_ancount;
    self->have_nscount = _self->dns.have_nscount;
    self->have_arcount = _self->dns.have_arcount;
    self->id = _self->dns.id;
    self->qr = _self->dns.qr;
    self->opcode = _self->dns.opcode;
    self->aa = _self->dns.aa;
    self->tc = _self->dns.tc;
    self->rd = _self->dns.rd;
    self->ra = _self->dns.ra;
    self->z = _self->dns.z;
    self->ad = _self->dns.ad;
    self->cd = _self->dns.cd;
    self->rcode = _self->dns.rcode;
    self->qdcount = _self->dns.qdcount;
    self->ancount = _self->dns.ancount;
    self->nscount = _self->dns.nscount;
    self->arcount = _self->dns.arcount;

    return 0;
}

const char* query_src(query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || _self->af == AF_UNSPEC) {
        return 0;
    }

    if (!inet_ntop(_self->af, &_self->src, _self->ntop_buf, NTOP_BUFSIZE)) {
        return 0;
    }

    return _self->ntop_buf;
}

const char* query_dst(query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || _self->af == AF_UNSPEC) {
        return 0;
    }

    if (!inet_ntop(_self->af, &_self->dst, _self->ntop_buf, NTOP_BUFSIZE)) {
        return 0;
    }

    return _self->ntop_buf;
}

int query_set_src(query_t* self, int af, const void* addr, size_t len)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !addr || !len || len > sizeof(struct sockaddr_storage)) {
        return 1;
    }

    if (_self->af != AF_UNSPEC && _self->af != af) {
        return 1;
    }

    memcpy(&_self->src, addr, len);
    _self->af = af;

    return 0;
}

int query_set_dst(query_t* self, int af, const void* addr, size_t len)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !addr || !len || len > sizeof(struct sockaddr_storage)) {
        return 1;
    }

    if (_self->af != AF_UNSPEC && _self->af != af) {
        return 1;
    }

    memcpy(&_self->dst, addr, len);
    _self->af = af;

    return 0;
}

int query_set_parsed_header(query_t* self, omg_dns_t dns)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !self->have_raw || !dns.have_header || dns.have_body || dns.is_complete) {
        return 1;
    }

    _self->dns = dns;
    self->have_id = dns.have_id;
    self->have_qr = dns.have_qr;
    self->have_opcode = dns.have_opcode;
    self->have_aa = dns.have_aa;
    self->have_tc = dns.have_tc;
    self->have_rd = dns.have_rd;
    self->have_ra = dns.have_ra;
    self->have_z = dns.have_z;
    self->have_ad = dns.have_ad;
    self->have_cd = dns.have_cd;
    self->have_rcode = dns.have_rcode;
    self->have_qdcount = dns.have_qdcount;
    self->have_ancount = dns.have_ancount;
    self->have_nscount = dns.have_nscount;
    self->have_arcount = dns.have_arcount;
    self->id = dns.id;
    self->qr = dns.qr;
    self->opcode = dns.opcode;
    self->aa = dns.aa;
    self->tc = dns.tc;
    self->rd = dns.rd;
    self->ra = dns.ra;
    self->z = dns.z;
    self->ad = dns.ad;
    self->cd = dns.cd;
    self->rcode = dns.rcode;
    self->qdcount = dns.qdcount;
    self->ancount = dns.ancount;
    self->nscount = dns.nscount;
    self->arcount = dns.arcount;

    return 0;
}

#define assert(a...)

inline int query_is_udp(const query_t* query)
{
    assert(query);
    return query->is_udp;
}

inline int query_is_tcp(const query_t* query)
{
    assert(query);
    return query->is_tcp;
}

inline int query_have_raw(const query_t* query)
{
    assert(query);
    return query->have_raw;
}

inline size_t query_length(const query_t* query)
{
    assert(query);
    return query->len;
}

inline const u_char* query_raw(const query_t* query)
{
    assert(query);
    return query->raw ? (u_char*)query->raw : (u_char*)query->small;
}

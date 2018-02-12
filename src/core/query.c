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
#include <sys/socket.h>

#if INET_ADDRSTRLEN > INET6_ADDRSTRLEN
#define NTOP_BUFSIZE INET_ADDRSTRLEN
#else
#define NTOP_BUFSIZE INET6_ADDRSTRLEN
#endif

#define NUM_LABELS 512
#define NUM_RRS 128

typedef struct _query {
    core_query_t pub;

    int                     af;
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    char                    ntop_buf[NTOP_BUFSIZE];

    omg_dns_t dns;

    unsigned short parsed : 1;
    size_t         rr_idx;
    omg_dns_rr_t   rr[NUM_RRS];
    int            rr_ret[NUM_RRS];
    size_t         rr_label_idx[NUM_RRS];

    size_t          label_idx;
    omg_dns_label_t label[NUM_LABELS];

    int  at_rr;
    char label_buf[512];
} _query_t;

static core_log_t   _log      = LOG_T_INIT("core.query");
static core_query_t _defaults = {
    LOG_T_INIT_OBJ("core.query"),
    0, 0, 0,
    0, 0, 0, 0,
    0, 0, { 0, 0 },
    "", 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0
};
static omg_dns_t _omg_dns_defaults = OMG_DNS_T_INIT;

core_log_t* core_query_log()
{
    return &_log;
}

static int _label_callback(const omg_dns_label_t* label, void* context)
{
    _query_t* _self = (_query_t*)context;

    if (!_self || _self->label_idx == NUM_LABELS)
        return OMG_DNS_ENOMEM;

    _self->label[_self->label_idx] = *label;
    _self->label_idx++;

    return OMG_DNS_OK;
}

static int _rr_callback(int ret, const omg_dns_rr_t* rr, void* context)
{
    _query_t* _self = (_query_t*)context;

    if (!_self || _self->rr_idx == NUM_RRS)
        return OMG_DNS_ENOMEM;

    _self->rr_ret[_self->rr_idx] = ret;
    if (rr)
        _self->rr[_self->rr_idx] = *rr;
    _self->rr_idx++;
    if (_self->rr_idx != NUM_RRS)
        _self->rr_label_idx[_self->rr_idx] = _self->label_idx;

    return OMG_DNS_OK;
}

core_query_t* core_query_new()
{
    core_query_t* self  = malloc(sizeof(_query_t));
    _query_t*     _self = (_query_t*)self;

    if (self) {
        *self         = _defaults;
        _self->af     = AF_UNSPEC;
        _self->dns    = _omg_dns_defaults;
        _self->parsed = 0;

        ldebug("new");

        omg_dns_set_rr_callback(&_self->dns, _rr_callback, (void*)_self);
        omg_dns_set_label_callback(&_self->dns, _label_callback, (void*)_self);
    }

    return self;
}

void core_query_free(core_query_t* self)
{
    ldebug("free");

    if (self) {
        free(self->raw);
        free(self);
    }
}

int core_query_set_raw(core_query_t* self, const char* raw, size_t len)
{
    if (!self || !raw || !len) {
        return 1;
    }

    ldebug("set raw %p %lu", raw, len);

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

core_query_t* core_query_copy(core_query_t* self)
{
    core_query_t* q = core_query_new();

    ldebug("copy %p", q);

    if (q) {
        _query_t* _q = (_query_t*)q;
        *_q          = *(_query_t*)self;
        q->have_raw  = 0;
        q->raw       = 0;
        q->len       = 0;

        if (!_q->parsed) {
            omg_dns_set_rr_callback(&_q->dns, _rr_callback, (void*)_q);
            omg_dns_set_label_callback(&_q->dns, _label_callback, (void*)_q);
        }

        if (self->have_raw) {
            core_query_set_raw(q, self->raw ? self->raw : self->small, self->len);
        }
    }

    return q;
}

int core_query_parse_header(core_query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !self->have_raw || _self->dns.have_header) {
        return 1;
    }

    if (omg_dns_parse_header(&_self->dns, (const u_char*)(self->raw ? self->raw : self->small), self->len)) {
        return 2;
    }

    self->have_id      = _self->dns.have_id;
    self->have_qr      = _self->dns.have_qr;
    self->have_opcode  = _self->dns.have_opcode;
    self->have_aa      = _self->dns.have_aa;
    self->have_tc      = _self->dns.have_tc;
    self->have_rd      = _self->dns.have_rd;
    self->have_ra      = _self->dns.have_ra;
    self->have_z       = _self->dns.have_z;
    self->have_ad      = _self->dns.have_ad;
    self->have_cd      = _self->dns.have_cd;
    self->have_rcode   = _self->dns.have_rcode;
    self->have_qdcount = _self->dns.have_qdcount;
    self->have_ancount = _self->dns.have_ancount;
    self->have_nscount = _self->dns.have_nscount;
    self->have_arcount = _self->dns.have_arcount;
    self->id           = _self->dns.id;
    self->qr           = _self->dns.qr;
    self->opcode       = _self->dns.opcode;
    self->aa           = _self->dns.aa;
    self->tc           = _self->dns.tc;
    self->rd           = _self->dns.rd;
    self->ra           = _self->dns.ra;
    self->z            = _self->dns.z;
    self->ad           = _self->dns.ad;
    self->cd           = _self->dns.cd;
    self->rcode        = _self->dns.rcode;
    self->qdcount      = _self->dns.qdcount;
    self->ancount      = _self->dns.ancount;
    self->nscount      = _self->dns.nscount;
    self->arcount      = _self->dns.arcount;

    return 0;
}

int core_query_parse(core_query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !self->have_raw || _self->parsed || _self->dns.have_body) {
        return 1;
    }

    _self->rr_idx    = 0;
    _self->label_idx = 0;
    if (!_self->dns.have_header) {
        if (omg_dns_parse(&_self->dns, (const u_char*)(self->raw ? self->raw : self->small), self->len)) {
            return 2;
        }

        self->have_id      = _self->dns.have_id;
        self->have_qr      = _self->dns.have_qr;
        self->have_opcode  = _self->dns.have_opcode;
        self->have_aa      = _self->dns.have_aa;
        self->have_tc      = _self->dns.have_tc;
        self->have_rd      = _self->dns.have_rd;
        self->have_ra      = _self->dns.have_ra;
        self->have_z       = _self->dns.have_z;
        self->have_ad      = _self->dns.have_ad;
        self->have_cd      = _self->dns.have_cd;
        self->have_rcode   = _self->dns.have_rcode;
        self->have_qdcount = _self->dns.have_qdcount;
        self->have_ancount = _self->dns.have_ancount;
        self->have_nscount = _self->dns.have_nscount;
        self->have_arcount = _self->dns.have_arcount;
        self->id           = _self->dns.id;
        self->qr           = _self->dns.qr;
        self->opcode       = _self->dns.opcode;
        self->aa           = _self->dns.aa;
        self->tc           = _self->dns.tc;
        self->rd           = _self->dns.rd;
        self->ra           = _self->dns.ra;
        self->z            = _self->dns.z;
        self->ad           = _self->dns.ad;
        self->cd           = _self->dns.cd;
        self->rcode        = _self->dns.rcode;
        self->qdcount      = _self->dns.qdcount;
        self->ancount      = _self->dns.ancount;
        self->nscount      = _self->dns.nscount;
        self->arcount      = _self->dns.arcount;
    } else if (self->len > _self->dns.bytes_parsed) {
        if (omg_dns_parse_body(&_self->dns, (const u_char*)(self->raw ? self->raw : self->small) + _self->dns.bytes_parsed, self->len - _self->dns.bytes_parsed)) {
            return 2;
        }
    }
    _self->parsed       = 1;
    _self->at_rr        = -1;
    _self->label_buf[0] = 0;

    self->questions   = _self->dns.questions;
    self->answers     = _self->dns.answers;
    self->authorities = _self->dns.authorities;
    self->additionals = _self->dns.additionals;

    return 0;
}

int core_query_rr_next(core_query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !_self->parsed) {
        return 1;
    }

    if (_self->at_rr < 0) {
        _self->at_rr = 0;
    } else if (_self->at_rr < _self->rr_idx) {
        _self->at_rr++;
    }

    return _self->at_rr < _self->rr_idx ? 0 : 1;
}

int core_query_rr_ok(core_query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !_self->parsed || _self->at_rr < 0 || _self->at_rr >= _self->rr_idx) {
        return 0;
    }

    return _self->rr_ret[_self->at_rr] == OMG_DNS_OK ? 1 : 0;
}

const char* core_query_rr_label(core_query_t* self)
{
    _query_t* _self = (_query_t*)self;
    char*     label;
    size_t    left;

    if (!_self || !_self->parsed || _self->at_rr < 0 || _self->at_rr >= _self->rr_idx || _self->rr_ret[_self->at_rr] != OMG_DNS_OK) {
        return 0;
    }

    label = _self->label_buf;
    left  = sizeof(_self->label) - 1;

    if (omg_dns_rr_labels(&_self->rr[_self->at_rr])) {
        size_t l    = _self->rr_label_idx[_self->at_rr];
        size_t loop = 0;

        while (!omg_dns_label_is_end(&(_self->label[l]))) {
            if (!omg_dns_label_is_complete(&(_self->label[l]))) {
                ldebug("label %lu incomplete", l);
                return 0;
            }

            if (loop > _self->label_idx) {
                ldebug("label %lu looped", l);
                return 0;
            }
            loop++;

            if (omg_dns_label_have_offset(&(_self->label[l]))) {
                size_t l2;

                for (l2 = 0; l2 < _self->label_idx; l2++) {
                    if (omg_dns_label_have_dn(&(_self->label[l2]))
                        && omg_dns_label_offset(&(_self->label[l2])) == omg_dns_label_offset(&(_self->label[l]))) {
                        l = l2;
                        break;
                    }
                }
                if (l2 < _self->label_idx) {
                    continue;
                }
                ldebug("label %lu offset missing", l);
                return 0;
            } else if (omg_dns_label_have_extension_bits(&(_self->label[l]))) {
                ldebug("label %lu is an extension", l);
                return 0;
            } else if (omg_dns_label_have_dn(&(_self->label[l]))) {
                char*  dn    = (self->raw ? self->raw : self->small) + omg_dns_label_dn_offset(&(_self->label[l]));
                size_t dnlen = omg_dns_label_length(&(_self->label[l]));

                if ((dnlen + 1) > left) {
                    ldebug("label %lu caused buffer overflow", l);
                    return 0;
                }
                memcpy(label, dn, dnlen);
                label += dnlen;
                left -= dnlen;

                *label = '.';
                label++;
                left--;

                l++;
            } else {
                ldebug("label %lu invalid", l);
                return 0;
            }
        }
    }

    *label = 0;
    return _self->label_buf;
}

uint16_t core_query_rr_type(core_query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !_self->parsed || _self->at_rr < 0 || _self->at_rr >= _self->rr_idx || _self->rr_ret[_self->at_rr] != OMG_DNS_OK) {
        return 0;
    }

    return _self->rr[_self->at_rr].type;
}

uint16_t core_query_rr_class(core_query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !_self->parsed || _self->at_rr < 0 || _self->at_rr >= _self->rr_idx || _self->rr_ret[_self->at_rr] != OMG_DNS_OK) {
        return 0;
    }

    return _self->rr[_self->at_rr].class;
}

uint32_t core_query_rr_ttl(core_query_t* self)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !_self->parsed || _self->at_rr < 0 || _self->at_rr >= _self->rr_idx || _self->rr_ret[_self->at_rr] != OMG_DNS_OK) {
        return 0;
    }

    return _self->rr[_self->at_rr].ttl;
}

const char* core_query_src(core_query_t* self)
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

const char* core_query_dst(core_query_t* self)
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

int core_query_set_src(core_query_t* self, int af, const void* addr, size_t len)
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

int core_query_set_dst(core_query_t* self, int af, const void* addr, size_t len)
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

int core_query_set_parsed_header(core_query_t* self, omg_dns_t dns)
{
    _query_t* _self = (_query_t*)self;

    if (!_self || !self->have_raw || !dns.have_header || dns.have_body || dns.is_complete) {
        return 1;
    }

    _self->dns         = dns;
    self->have_id      = dns.have_id;
    self->have_qr      = dns.have_qr;
    self->have_opcode  = dns.have_opcode;
    self->have_aa      = dns.have_aa;
    self->have_tc      = dns.have_tc;
    self->have_rd      = dns.have_rd;
    self->have_ra      = dns.have_ra;
    self->have_z       = dns.have_z;
    self->have_ad      = dns.have_ad;
    self->have_cd      = dns.have_cd;
    self->have_rcode   = dns.have_rcode;
    self->have_qdcount = dns.have_qdcount;
    self->have_ancount = dns.have_ancount;
    self->have_nscount = dns.have_nscount;
    self->have_arcount = dns.have_arcount;
    self->id           = dns.id;
    self->qr           = dns.qr;
    self->opcode       = dns.opcode;
    self->aa           = dns.aa;
    self->tc           = dns.tc;
    self->rd           = dns.rd;
    self->ra           = dns.ra;
    self->z            = dns.z;
    self->ad           = dns.ad;
    self->cd           = dns.cd;
    self->rcode        = dns.rcode;
    self->qdcount      = dns.qdcount;
    self->ancount      = dns.ancount;
    self->nscount      = dns.nscount;
    self->arcount      = dns.arcount;

    return 0;
}

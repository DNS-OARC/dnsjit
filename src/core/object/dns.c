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

#include "core/object/dns.h"
#include "omg-dns/omg_dns.h"

#include <string.h>

#define NUM_LABELS 128
#define NUM_RRS 64

typedef struct _parse {
    size_t          rr_idx;
    omg_dns_rr_t    rr[NUM_RRS];
    int             rr_ret[NUM_RRS];
    size_t          rr_label_idx[NUM_RRS];
    size_t          label_idx;
    omg_dns_label_t label[NUM_LABELS];
    int             at_rr;
    char            label_buf[512];
} _parse_t;

typedef struct _query {
    core_object_dns_t pub;
    omg_dns_t         dns;
    _parse_t*         parsed;
} _query_t;

static core_log_t _log      = LOG_T_INIT("core.object.dns");
static _query_t   _defaults = {
    CORE_OBJECT_DNS_INIT,
    OMG_DNS_T_INIT,
    0
};

#define _self ((_query_t*)self)

core_log_t* core_object_dns_log()
{
    return &_log;
}

static int _label_callback(const omg_dns_label_t* label, void* self)
{
    if (!_self || _self->parsed->label_idx == NUM_LABELS)
        return OMG_DNS_ENOMEM;

    _self->parsed->label[_self->parsed->label_idx] = *label;
    _self->parsed->label_idx++;

    return OMG_DNS_OK;
}

static int _rr_callback(int ret, const omg_dns_rr_t* rr, void* self)
{
    if (!_self || _self->parsed->rr_idx == NUM_RRS)
        return OMG_DNS_ENOMEM;

    _self->parsed->rr_ret[_self->parsed->rr_idx] = ret;
    if (rr)
        _self->parsed->rr[_self->parsed->rr_idx] = *rr;
    _self->parsed->rr_idx++;
    if (_self->parsed->rr_idx != NUM_RRS)
        _self->parsed->rr_label_idx[_self->parsed->rr_idx] = _self->parsed->label_idx;

    return OMG_DNS_OK;
}

core_object_dns_t* core_object_dns_new(const core_object_packet_t* pkt)
{
    core_object_dns_t* self = malloc(sizeof(_query_t));

    if (self) {
        *_self         = _defaults;
        self->obj_prev = (core_object_t*)pkt;
    }

    return self;
}

void core_object_dns_free(core_object_dns_t* self)
{
    if (self) {
        free(_self->parsed);
        free(self);
    }
}

int core_object_dns_parse_header(core_object_dns_t* self)
{
    const core_object_packet_t* pkt;

    if (!_self || _self->dns.have_header) {
        return 1;
    }

    for (pkt = (core_object_packet_t*)self->obj_prev; pkt && pkt->obj_type != CORE_OBJECT_PACKET; pkt = (core_object_packet_t*)pkt->obj_prev)
        ;
    if (!pkt) {
        return 1;
    }

    if (omg_dns_parse_header(&_self->dns, (u_char*)pkt->payload, pkt->len)) {
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

int core_object_dns_parse(core_object_dns_t* self)
{
    const core_object_packet_t* pkt;

    if (!_self || _self->parsed || _self->dns.have_body) {
        return 1;
    }

    for (pkt = (core_object_packet_t*)self->obj_prev; pkt && pkt->obj_type != CORE_OBJECT_PACKET; pkt = (core_object_packet_t*)pkt->obj_prev)
        ;
    if (!pkt) {
        return 1;
    }

    if (!(_self->parsed = malloc(sizeof(_parse_t)))) {
        return 1;
    }

    _self->parsed->rr_idx    = 0;
    _self->parsed->label_idx = 0;

    omg_dns_set_rr_callback(&_self->dns, _rr_callback, (void*)_self);
    omg_dns_set_label_callback(&_self->dns, _label_callback, (void*)_self);

    if (!_self->dns.have_header) {
        if (omg_dns_parse(&_self->dns, (u_char*)pkt->payload, pkt->len)) {
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
    } else if (pkt->len > _self->dns.bytes_parsed) {
        if (omg_dns_parse_body(&_self->dns, (u_char*)pkt->payload + _self->dns.bytes_parsed, pkt->len - _self->dns.bytes_parsed)) {
            return 2;
        }
    }
    _self->parsed->at_rr        = -1;
    _self->parsed->label_buf[0] = 0;

    self->questions   = _self->dns.questions;
    self->answers     = _self->dns.answers;
    self->authorities = _self->dns.authorities;
    self->additionals = _self->dns.additionals;

    return 0;
}

int core_object_dns_rr_next(core_object_dns_t* self)
{
    if (!_self || !_self->parsed) {
        return 1;
    }

    if (_self->parsed->at_rr < 0) {
        _self->parsed->at_rr = 0;
    } else if (_self->parsed->at_rr < _self->parsed->rr_idx) {
        _self->parsed->at_rr++;
    }

    return _self->parsed->at_rr < _self->parsed->rr_idx ? 0 : -1;
}

int core_object_dns_rr_ok(core_object_dns_t* self)
{
    if (!_self || !_self->parsed || _self->parsed->at_rr < 0 || _self->parsed->at_rr >= _self->parsed->rr_idx) {
        return 0;
    }

    return _self->parsed->rr_ret[_self->parsed->at_rr] == OMG_DNS_OK ? 1 : 0;
}

const char* core_object_dns_rr_label(core_object_dns_t* self)
{
    const core_object_packet_t* pkt;
    char*                       label;
    size_t                      left;

    if (!_self || !_self->parsed || _self->parsed->at_rr < 0 || _self->parsed->at_rr >= _self->parsed->rr_idx || _self->parsed->rr_ret[_self->parsed->at_rr] != OMG_DNS_OK) {
        return 0;
    }

    for (pkt = (core_object_packet_t*)self->obj_prev; pkt && pkt->obj_type != CORE_OBJECT_PACKET; pkt = (core_object_packet_t*)pkt->obj_prev)
        ;
    if (!pkt) {
        return 0;
    }

    label = _self->parsed->label_buf;
    left  = sizeof(_self->parsed->label_buf) - 1;

    if (omg_dns_rr_labels(&_self->parsed->rr[_self->parsed->at_rr])) {
        size_t l    = _self->parsed->rr_label_idx[_self->parsed->at_rr];
        size_t loop = 0;

        while (!omg_dns_label_is_end(&(_self->parsed->label[l]))) {
            if (!omg_dns_label_is_complete(&(_self->parsed->label[l]))) {
                mldebug("label %lu incomplete", l);
                return 0;
            }

            if (loop > _self->parsed->label_idx) {
                mldebug("label %lu looped", l);
                return 0;
            }
            loop++;

            if (omg_dns_label_have_offset(&(_self->parsed->label[l]))) {
                size_t l2;

                for (l2 = 0; l2 < _self->parsed->label_idx; l2++) {
                    if (omg_dns_label_have_dn(&(_self->parsed->label[l2]))
                        && omg_dns_label_offset(&(_self->parsed->label[l2])) == omg_dns_label_offset(&(_self->parsed->label[l]))) {
                        l = l2;
                        break;
                    }
                }
                if (l2 < _self->parsed->label_idx) {
                    continue;
                }
                mldebug("label %lu offset missing", l);
                return 0;
            } else if (omg_dns_label_have_extension_bits(&(_self->parsed->label[l]))) {
                mldebug("label %lu is an extension", l);
                return 0;
            } else if (omg_dns_label_have_dn(&(_self->parsed->label[l]))) {
                const char* dn    = (char*)pkt->payload + omg_dns_label_dn_offset(&(_self->parsed->label[l]));
                size_t      dnlen = omg_dns_label_length(&(_self->parsed->label[l]));

                if ((dnlen + 1) > left) {
                    mldebug("label %lu caused buffer overflow", l);
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
                mldebug("label %lu invalid", l);
                return 0;
            }
        }
    }

    *label = 0;
    return _self->parsed->label_buf;
}

uint16_t core_object_dns_rr_type(core_object_dns_t* self)
{
    if (!_self || !_self->parsed || _self->parsed->at_rr < 0 || _self->parsed->at_rr >= _self->parsed->rr_idx || _self->parsed->rr_ret[_self->parsed->at_rr] != OMG_DNS_OK) {
        return 0;
    }

    return _self->parsed->rr[_self->parsed->at_rr].type;
}

uint16_t core_object_dns_rr_class(core_object_dns_t* self)
{
    if (!_self || !_self->parsed || _self->parsed->at_rr < 0 || _self->parsed->at_rr >= _self->parsed->rr_idx || _self->parsed->rr_ret[_self->parsed->at_rr] != OMG_DNS_OK) {
        return 0;
    }

    return _self->parsed->rr[_self->parsed->at_rr].class;
}

uint32_t core_object_dns_rr_ttl(core_object_dns_t* self)
{
    if (!_self || !_self->parsed || _self->parsed->at_rr < 0 || _self->parsed->at_rr >= _self->parsed->rr_idx || _self->parsed->rr_ret[_self->parsed->at_rr] != OMG_DNS_OK) {
        return 0;
    }

    return _self->parsed->rr[_self->parsed->at_rr].ttl;
}

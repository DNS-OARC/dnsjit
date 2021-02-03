/*
 * Copyright (c) 2018-2021, OARC, Inc.
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
#include "core/object/payload.h"
#include "core/assert.h"

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#else
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#else
#ifdef HAVE_MACHINE_ENDIAN_H
#include <machine/endian.h>
#endif
#endif
#endif
#ifdef HAVE_BYTESWAP_H
#include <byteswap.h>
#endif
#ifndef bswap_16
#ifndef bswap16
#define bswap_16(x) swap16(x)
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)
#else
#define bswap_16(x) bswap16(x)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#endif
#endif

#define _ERR_MALFORMED -2
#define _ERR_NEEDLABELS -3

static core_log_t        _log      = LOG_T_INIT("core.object.dns");
static core_object_dns_t _defaults = CORE_OBJECT_DNS_INIT(0);

static core_object_dns_label_t _defaults_label = { 0 };
static core_object_dns_rr_t    _defaults_rr    = { 0 };
static core_object_dns_q_t     _defaults_q     = { 0 };

core_log_t* core_object_dns_log()
{
    return &_log;
}

core_object_dns_t* core_object_dns_new()
{
    core_object_dns_t* self;

    mlfatal_oom(self = malloc(sizeof(core_object_dns_t)));
    *self = _defaults;

    return self;
}

core_object_dns_t* core_object_dns_copy(const core_object_dns_t* self)
{
    core_object_dns_t* copy;
    mlassert_self();

    mlfatal_oom(copy = malloc(sizeof(core_object_dns_t)));
    memcpy(copy, self, sizeof(core_object_dns_t));
    copy->obj_prev = 0;

    return (core_object_dns_t*)copy;
}

void core_object_dns_free(core_object_dns_t* self)
{
    mlassert_self();
    free(self);
}

#define need8(v, p, l) \
    if (l < 1) {       \
        break;         \
    }                  \
    v = *p;            \
    p += 1;            \
    l -= 1

static inline uint16_t _need16(const void* ptr)
{
    uint16_t v;
    memcpy(&v, ptr, sizeof(v));
    return be16toh(v);
}

#define need16(v, p, l) \
    if (l < 2) {        \
        break;          \
    }                   \
    v = _need16(p);     \
    p += 2;             \
    l -= 2

static inline uint32_t _need32(const void* ptr)
{
    uint32_t v;
    memcpy(&v, ptr, sizeof(v));
    return be32toh(v);
}

#define need32(v, p, l) \
    if (l < 4) {        \
        break;          \
    }                   \
    v = _need32(p);     \
    p += 4;             \
    l -= 4

#define needxb(b, x, p, l) \
    if (l < x) {           \
        break;             \
    }                      \
    memcpy(b, p, x);       \
    p += x;                \
    l -= x

#define advancexb(x, p, l) \
    if (l < x) {           \
        break;             \
    }                      \
    p += x;                \
    l -= x

int core_object_dns_parse_header(core_object_dns_t* self)
{
    const core_object_payload_t* payload;
    uint8_t                      byte;
    mlassert_self();

    if (!(payload = (core_object_payload_t*)self->obj_prev) || payload->obj_type != CORE_OBJECT_PAYLOAD) {
        mlfatal("no obj_prev or invalid type");
    }
    if (!payload->payload || !payload->len) {
        mlfatal("no payload set or zero length");
    }

    self->payload = self->at = payload->payload;
    self->len = self->left = payload->len;

    for (;;) {
        if (self->includes_dnslen) {
            need16(self->dnslen, self->at, self->left);
            self->have_dnslen = 1;
        }
        need16(self->id, self->at, self->left);
        self->have_id = 1;

        need8(byte, self->at, self->left);
        self->qr      = byte & (1 << 7) ? 1 : 0;
        self->opcode  = (byte >> 3) & 0xf;
        self->aa      = byte & (1 << 2) ? 1 : 0;
        self->tc      = byte & (1 << 1) ? 1 : 0;
        self->rd      = byte & (1 << 0) ? 1 : 0;
        self->have_qr = self->have_opcode = self->have_aa = self->have_tc = self->have_rd = 1;

        need8(byte, self->at, self->left);
        self->ra      = byte & (1 << 7) ? 1 : 0;
        self->z       = byte & (1 << 6) ? 1 : 0;
        self->ad      = byte & (1 << 5) ? 1 : 0;
        self->cd      = byte & (1 << 4) ? 1 : 0;
        self->rcode   = byte & 0xf;
        self->have_ra = self->have_z = self->have_ad = self->have_cd = self->have_rcode = 1;

        need16(self->qdcount, self->at, self->left);
        self->have_qdcount = 1;

        need16(self->ancount, self->at, self->left);
        self->have_ancount = 1;

        need16(self->nscount, self->at, self->left);
        self->have_nscount = 1;

        need16(self->arcount, self->at, self->left);
        self->have_arcount = 1;

        return 0;
    }

    // TODO: error here on malformed/truncated? could be quite spammy
    return _ERR_MALFORMED;
}

static inline size_t _rdata_labels(uint16_t type)
{
    switch (type) {
    case CORE_OBJECT_DNS_TYPE_NS:
    case CORE_OBJECT_DNS_TYPE_MD:
    case CORE_OBJECT_DNS_TYPE_MF:
    case CORE_OBJECT_DNS_TYPE_CNAME:
    case CORE_OBJECT_DNS_TYPE_MB:
    case CORE_OBJECT_DNS_TYPE_MG:
    case CORE_OBJECT_DNS_TYPE_MR:
    case CORE_OBJECT_DNS_TYPE_PTR:
    case CORE_OBJECT_DNS_TYPE_NXT:
    case CORE_OBJECT_DNS_TYPE_DNAME:
    case CORE_OBJECT_DNS_TYPE_NSEC:
    case CORE_OBJECT_DNS_TYPE_TKEY:
    case CORE_OBJECT_DNS_TYPE_TSIG:
        return 1;

    case CORE_OBJECT_DNS_TYPE_SOA:
    case CORE_OBJECT_DNS_TYPE_MINFO:
    case CORE_OBJECT_DNS_TYPE_RP:
    case CORE_OBJECT_DNS_TYPE_TALINK:
        return 2;

    case CORE_OBJECT_DNS_TYPE_MX:
    case CORE_OBJECT_DNS_TYPE_AFSDB:
    case CORE_OBJECT_DNS_TYPE_RT:
    case CORE_OBJECT_DNS_TYPE_KX:
    case CORE_OBJECT_DNS_TYPE_LP:
        return 1;

    case CORE_OBJECT_DNS_TYPE_PX:
        return 2;

    case CORE_OBJECT_DNS_TYPE_SIG:
    case CORE_OBJECT_DNS_TYPE_RRSIG:
        return 1;

    case CORE_OBJECT_DNS_TYPE_SRV:
        return 1;

    case CORE_OBJECT_DNS_TYPE_NAPTR:
        return 1;

    case CORE_OBJECT_DNS_TYPE_HIP:
        return 1;

    default:
        break;
    }

    return 0;
}

static inline size_t _label(core_object_dns_t* self, core_object_dns_label_t* label, size_t labels)
{
    size_t n;

    for (n = 0; self->left && n < labels; n++) {
        core_object_dns_label_t* l = &label[n];
        *l                         = _defaults_label;

        need8(l->length, self->at, self->left);

        if ((l->length & 0xc0) == 0xc0) {
            need8(l->offset, self->at, self->left);
            l->offset |= (l->length & 0x3f) << 8;
            l->have_offset = 1;
            return n;
        } else if (l->length & 0xc0) {
            l->extension_bits      = l->length >> 6;
            l->have_extension_bits = 1;
            return n;
        } else if (l->length) {
            l->have_length = 1;

            l->offset = self->at - self->payload - 1;
            advancexb(l->length, self->at, self->left);
            l->have_dn = 1;
        } else {
            l->is_end = 1;
            return n;
        }
    }

    return n;
}

int core_object_dns_parse_q(core_object_dns_t* self, core_object_dns_q_t* q, core_object_dns_label_t* label, size_t labels)
{
    mlassert_self();
    mlassert(q, "q is nil");
    mlassert(label, "label is nil");
    mlassert(labels, "labels is zero");
    mlassert(self->at, "at is nil");

    for (;;) {
        *q        = _defaults_q;
        q->labels = _label(self, label, labels);
        if (q->labels < labels) {
            core_object_dns_label_t* l = &label[q->labels];
            if (!(l->have_offset | l->have_extension_bits | l->is_end)) {
                // TODO: error here on malformed/truncated? could be quite spammy
                return _ERR_MALFORMED;
            }
        } else {
            mlwarning("need more labels, aborting DNS parsing");
            return _ERR_NEEDLABELS;
        }
        q->labels++;

        need16(q->type, self->at, self->left);
        q->have_type = 1;

        need16(q->class, self->at, self->left);
        q->have_class = 1;

        return 0;
    }

    // TODO: error here on malformed/truncated? could be quite spammy
    return _ERR_MALFORMED;
}

int core_object_dns_parse_rr(core_object_dns_t* self, core_object_dns_rr_t* rr, core_object_dns_label_t* label, size_t labels)
{
    size_t rdata_label_sets;
    mlassert_self();
    mlassert(rr, "rr is nil");
    mlassert(label, "label is nil");
    mlassert(labels, "labels is zero");
    mlassert(self->at, "at is nil");

    for (;;) {
        *rr        = _defaults_rr;
        rr->labels = _label(self, label, labels);
        if (rr->labels < labels) {
            core_object_dns_label_t* l = &label[rr->labels];
            if (!(l->have_offset | l->have_extension_bits | l->is_end)) {
                // TODO: error here on malformed/truncated? could be quite spammy
                return _ERR_MALFORMED;
            }
        } else {
            mlwarning("need more labels, aborting DNS parsing");
            return _ERR_NEEDLABELS;
        }
        rr->labels++;

        need16(rr->type, self->at, self->left);
        rr->have_type = 1;

        need16(rr->class, self->at, self->left);
        rr->have_class = 1;

        need32(rr->ttl, self->at, self->left);
        rr->have_ttl = 1;

        need16(rr->rdlength, self->at, self->left);
        rr->have_rdlength = 1;

        rr->rdata_offset = self->at - self->payload;
        if (!(rdata_label_sets = _rdata_labels(rr->type))) {
            advancexb(rr->rdlength, self->at, self->left);
            rr->have_rdata = 1;
            return 0;
        }

        switch (rr->type) {
        case CORE_OBJECT_DNS_TYPE_MX:
        case CORE_OBJECT_DNS_TYPE_AFSDB:
        case CORE_OBJECT_DNS_TYPE_RT:
        case CORE_OBJECT_DNS_TYPE_KX:
        case CORE_OBJECT_DNS_TYPE_LP:
        case CORE_OBJECT_DNS_TYPE_PX:
            advancexb(2, self->at, self->left);
            break;

        case CORE_OBJECT_DNS_TYPE_SIG:
        case CORE_OBJECT_DNS_TYPE_RRSIG:
            advancexb(18, self->at, self->left);
            break;

        case CORE_OBJECT_DNS_TYPE_SRV:
            advancexb(6, self->at, self->left);
            break;

        case CORE_OBJECT_DNS_TYPE_NAPTR: {
            uint8_t naptr_length;

            advancexb(4, self->at, self->left);
            need8(naptr_length, self->at, self->left);
            advancexb(naptr_length, self->at, self->left);
            need8(naptr_length, self->at, self->left);
            advancexb(naptr_length, self->at, self->left);
            need8(naptr_length, self->at, self->left);
            advancexb(naptr_length, self->at, self->left);
        } break;

        case CORE_OBJECT_DNS_TYPE_HIP: {
            uint8_t  hit_length;
            uint16_t pk_length;

            need8(hit_length, self->at, self->left);
            advancexb(1, self->at, self->left);
            need16(pk_length, self->at, self->left);
            advancexb(hit_length, self->at, self->left);
            advancexb(pk_length, self->at, self->left);

            if (self->at - self->payload >= rr->rdata_offset + rr->rdlength) {
                rdata_label_sets = 0;
            }
        } break;
        }

        while (rdata_label_sets) {
            rr->rdata_labels += _label(self, &label[rr->labels + rr->rdata_labels], labels - rr->labels - rr->rdata_labels);
            if (rr->labels + rr->rdata_labels < labels) {
                core_object_dns_label_t* l = &label[rr->labels + rr->rdata_labels];
                if (!(l->have_offset | l->have_extension_bits | l->is_end)) {
                    // TODO: error here on malformed/truncated? could be quite spammy
                    return _ERR_MALFORMED;
                }
            } else {
                mlwarning("need more labels, aborting DNS parsing");
                return _ERR_NEEDLABELS;
            }
            rr->rdata_labels++;

            if (rr->type == CORE_OBJECT_DNS_TYPE_HIP && self->at - self->payload < rr->rdata_offset + rr->rdlength) {
                continue;
            }

            rdata_label_sets--;
        }

        if (self->at - self->payload < rr->rdata_offset + rr->rdlength) {
            rr->padding_offset = self->at - self->payload;
            rr->padding_length = rr->rdlength - (rr->padding_offset - rr->rdata_offset);

            advancexb(rr->padding_length, self->at, self->left);

            /*
             * TODO:
             *
             * This can indicate padding but we do not set that we have padding
             * yet because we need to fully understand all record types before
             * that and process valid data after the labels
             *
            rr->have_padding = 1;
             */
        } else if (self->at - self->payload > rr->rdata_offset + rr->rdlength) {
            // TODO: error here on malformed/truncated? could be quite spammy
            return _ERR_MALFORMED;
        }
        rr->have_rdata = 1;

        return 0;
    }

    // TODO: error here on malformed/truncated? could be quite spammy
    return _ERR_MALFORMED;
}

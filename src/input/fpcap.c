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

#include "input/fpcap.h"
#include "core/object/pcap.h"

#include <time.h>
#include <stdio.h>
#include <pthread.h>

static core_log_t    _log      = LOG_T_INIT("input.fpcap");
static input_fpcap_t _defaults = {
    LOG_T_INIT_OBJ("input.fpcap"),
    0, 0,
    0, 0, 0,
    0, 10000, 100,
    0, { 0, 0 }, { 0, 0 }, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0
};

struct _ctx {
    pthread_mutex_t m;
    pthread_cond_t  c;
    size_t          ref;
};

static void _ref(core_object_t* obj, core_object_reference_t ref)
{
    struct _ctx* ctx = (struct _ctx*)obj->obj_refctx;

    pthread_mutex_lock(&ctx->m);
    if (ref == CORE_OBJECT_INCREF) {
        ctx->ref++;
    } else {
        ctx->ref--;
        if (!ctx->ref)
            pthread_cond_signal(&ctx->c);
    }
    pthread_mutex_unlock(&ctx->m);
}

core_log_t* input_fpcap_log()
{
    return &_log;
}

int input_fpcap_init(input_fpcap_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    return 0;
}

int input_fpcap_destroy(input_fpcap_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    if (self->file) {
        fclose(self->file);
    }
    free(self->buf);
    free(self->shared_pkts);

    return 0;
}

static inline uint16_t _flip16(uint16_t u16)
{
    return ((u16 & 0xff) << 8) | (u16 >> 8);
}

static inline uint32_t _flip32(uint32_t u32)
{
    return ((u32 & 0xff) << 24) | ((u32 & 0xff00) << 8) | ((u32 & 0xff0000) >> 8) | (u32 >> 24);
}

int input_fpcap_open(input_fpcap_t* self, const char* file)
{
    int ret;

    if (!self || !file) {
        return 1;
    }

    if (self->file) {
        fclose(self->file);
        self->file = 0;
    }
    free(self->buf);
    self->buf = 0;
    free(self->shared_pkts);
    self->shared_pkts = 0;

    if (!(self->file = fopen(file, "rb"))) {
        return 1;
    }

    if ((ret = fread(&self->magic_number, 1, 24, self->file)) != 24) {
        fclose(self->file);
        self->file = 0;
        return 1;
    }
    switch (self->magic_number) {
    case 0x4d3cb2a1:
        self->is_nanosec = 1;
    case 0xd4c3b2a1:
        self->is_swapped    = 1;
        self->version_major = _flip16(self->version_major);
        self->version_minor = _flip16(self->version_minor);
        self->thiszone      = (int32_t)_flip32((uint32_t)self->thiszone);
        self->sigfigs       = _flip32(self->sigfigs);
        self->snaplen       = _flip32(self->snaplen);
        self->network       = _flip32(self->network);
        break;
    case 0xa1b2c3d4:
    case 0xa1b23c4d:
        break;
    default:
        fclose(self->file);
        self->file = 0;
        return 2;
    }

    if (self->version_major == 2 && self->version_minor == 4) {
        if (self->use_shared) {
            size_t n;

            self->buf_size = self->num_shared_pkts * 1500;
            if (!(self->buf = malloc(self->buf_size))) {
                fclose(self->file);
                self->file = 0;
                return 1;
            }

            if (!(self->shared_pkts = malloc(sizeof(core_object_pcap_t) * self->num_shared_pkts))) {
                fclose(self->file);
                self->file = 0;
                return 1;
            }

            for (n = 0; n < self->num_shared_pkts; n++) {
                self->shared_pkts[n].obj_type   = CORE_OBJECT_PCAP;
                self->shared_pkts[n].snaplen    = self->snaplen;
                self->shared_pkts[n].linktype   = self->network;
                self->shared_pkts[n].bytes      = 0;
                self->shared_pkts[n].is_swapped = self->is_swapped;
                self->shared_pkts[n].obj_ref    = _ref;
            }
        } else {
            if (!(self->buf = malloc(self->snaplen))) {
                fclose(self->file);
                self->file = 0;
                return 1;
            }
        }
        ldebug("pcap v%u.%u snaplen:%lu %s", self->version_major, self->version_minor, self->snaplen, self->is_swapped ? " swapped" : "");
        return 0;
    }

    fclose(self->file);
    self->file = 0;
    return 2;
}

static int _run(input_fpcap_t* self)
{
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } hdr;
    core_object_pcap_t pkt = CORE_OBJECT_PCAP_INIT(0);

    pkt.snaplen    = self->snaplen;
    pkt.linktype   = self->network;
    pkt.bytes      = (unsigned char*)self->buf;
    pkt.is_swapped = self->is_swapped;

    while (fread(&hdr, 1, 16, self->file) == 16) {
        if (self->is_swapped) {
            hdr.ts_sec   = _flip32(hdr.ts_sec);
            hdr.ts_usec  = _flip32(hdr.ts_usec);
            hdr.incl_len = _flip32(hdr.incl_len);
            hdr.orig_len = _flip32(hdr.orig_len);
        }
        if (hdr.incl_len > self->snaplen) {
            return 2;
        }
        if (fread(self->buf, 1, hdr.incl_len, self->file) != hdr.incl_len) {
            return 3;
        }

        self->pkts++;

        pkt.ts.sec = hdr.ts_sec;
        if (self->is_nanosec) {
            pkt.ts.nsec = hdr.ts_usec;
        } else {
            pkt.ts.nsec = hdr.ts_usec * 1000;
        }
        pkt.caplen = hdr.incl_len;
        pkt.len    = hdr.orig_len;

        self->recv(self->ctx, (core_object_t*)&pkt);
    }

    return 0;
}

static int _run_shared(input_fpcap_t* self)
{
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } hdr;
    struct _ctx ctx = {
        .m   = PTHREAD_MUTEX_INITIALIZER,
        .c   = PTHREAD_COND_INITIALIZER,
        .ref = 0
    };
    size_t   n, m, buf_left;
    uint8_t* bufp;

    for (n = 0; n < self->num_shared_pkts; n++) {
        self->shared_pkts[n].obj_refctx  = (void*)&ctx;
        self->shared_pkts[n].is_multiple = 1;
    }

    n        = 0;
    m        = 0;
    bufp     = self->buf;
    buf_left = self->buf_size;

    while (fread(&hdr, 1, 16, self->file) == 16) {
        if (self->is_swapped) {
            hdr.ts_sec   = _flip32(hdr.ts_sec);
            hdr.ts_usec  = _flip32(hdr.ts_usec);
            hdr.incl_len = _flip32(hdr.incl_len);
            hdr.orig_len = _flip32(hdr.orig_len);
        }
        if (hdr.incl_len > buf_left || n == self->num_shared_pkts) {
            if (m) {
                self->recv(self->ctx, (core_object_t*)&self->shared_pkts[n - 1]);
            }
            pthread_mutex_lock(&ctx.m);
            while (ctx.ref) {
                pthread_cond_wait(&ctx.c, &ctx.m);
            }
            pthread_mutex_unlock(&ctx.m);

            n        = 0;
            m        = 0;
            bufp     = self->buf;
            buf_left = self->buf_size;
        }
        if (fread(bufp, 1, hdr.incl_len, self->file) != hdr.incl_len) {
            return 3;
        }

        self->pkts++;

        self->shared_pkts[n].ts.sec = hdr.ts_sec;
        if (self->is_nanosec) {
            self->shared_pkts[n].ts.nsec = hdr.ts_usec;
        } else {
            self->shared_pkts[n].ts.nsec = hdr.ts_usec * 1000;
        }
        self->shared_pkts[n].caplen = hdr.incl_len;
        self->shared_pkts[n].len    = hdr.orig_len;
        self->shared_pkts[n].bytes  = bufp;

        if (!m) {
            self->shared_pkts[n].obj_prev = 0;
        } else {
            self->shared_pkts[n].obj_prev = (core_object_t*)&self->shared_pkts[n - 1];
        }
        m++;
        if (m == self->num_multiple_pkts) {
            self->recv(self->ctx, (core_object_t*)&self->shared_pkts[n]);
            m = 0;
        }

        bufp += hdr.incl_len;
        buf_left -= hdr.incl_len;
        n++;
    }

    if (m) {
        self->recv(self->ctx, (core_object_t*)&self->shared_pkts[n - 1]);
    }
    pthread_mutex_lock(&ctx.m);
    while (ctx.ref) {
        pthread_cond_wait(&ctx.c, &ctx.m);
    }
    pthread_mutex_unlock(&ctx.m);

    return 0;
}

int input_fpcap_run(input_fpcap_t* self)
{
    struct timespec ts;
    int             ret;

    if (!self || !self->file || !self->recv) {
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts);
    self->ts.sec  = ts.tv_sec;
    self->ts.nsec = ts.tv_nsec;

    if (self->use_shared) {
        ret = _run_shared(self);
    } else {
        ret = _run(self);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts);
    self->te.sec  = ts.tv_sec;
    self->te.nsec = ts.tv_nsec;

    return ret;
}

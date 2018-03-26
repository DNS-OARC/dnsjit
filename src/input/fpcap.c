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

static core_log_t    _log      = LOG_T_INIT("input.fpcap");
static input_fpcap_t _defaults = {
    LOG_T_INIT_OBJ("input.fpcap"),
    0, 0,
    0, 0,
    0, { 0, 0 }, { 0, 0 }, 0, 0,
    0, 0, 0, 0, 0, 0, 0
};

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
    if (self->buf) {
        free(self->buf);
    }

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
    if (self->buf) {
        free(self->buf);
        self->buf = 0;
    }

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
        if (!(self->buf = malloc(self->snaplen))) {
            fclose(self->file);
            self->file = 0;
            return 1;
        }
        ldebug("pcap v%u.%u snaplen:%lu %s", self->version_major, self->version_minor, self->snaplen, self->is_swapped ? " swapped" : "");
        return 0;
    }

    fclose(self->file);
    self->file = 0;
    return 2;
}

int input_fpcap_run(input_fpcap_t* self)
{
    struct timespec ts;
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } hdr;
    core_object_pcap_t pkt = CORE_OBJECT_PCAP_INIT(0);

    if (!self || !self->file || !self->recv) {
        return 1;
    }

    pkt.snaplen    = self->snaplen;
    pkt.linktype   = self->network;
    pkt.bytes      = (unsigned char*)self->buf;
    pkt.is_swapped = self->is_swapped;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    self->ts.sec  = ts.tv_sec;
    self->ts.nsec = ts.tv_nsec;

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

    clock_gettime(CLOCK_MONOTONIC, &ts);
    self->te.sec  = ts.tv_sec;
    self->te.nsec = ts.tv_nsec;

    return 0;
}

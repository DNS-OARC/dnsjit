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

#include "input/fpcap.h"
#include "core/assert.h"
#include "core/object/pcap.h"

#include <fcntl.h>
#include <stdio.h>
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
#include <pcap/pcap.h>

#define MAX_SNAPLEN 0x40000

static core_log_t    _log      = LOG_T_INIT("input.fpcap");
static input_fpcap_t _defaults = {
    LOG_T_INIT_OBJ("input.fpcap"),
    0, 0,
    0, 0, 0,
    CORE_OBJECT_PCAP_INIT(0),
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
    0
};

core_log_t* input_fpcap_log()
{
    return &_log;
}

void input_fpcap_init(input_fpcap_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void input_fpcap_destroy(input_fpcap_t* self)
{
    mlassert_self();

    if (!self->extern_file && self->file) {
        fclose(self->file);
    }
    free(self->buf);
}

static int _open(input_fpcap_t* self)
{
    mlassert_self();
    int fd = fileno(self->file);
    if (fd != -1)
        (void)posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    if (fread(&self->magic_number, 1, 4, self->file) != 4
        || fread(&self->version_major, 1, 2, self->file) != 2
        || fread(&self->version_minor, 1, 2, self->file) != 2
        || fread(&self->thiszone, 1, 4, self->file) != 4
        || fread(&self->sigfigs, 1, 4, self->file) != 4
        || fread(&self->snaplen, 1, 4, self->file) != 4
        || fread(&self->network, 1, 4, self->file) != 4) {
        lcritical("could not read full PCAP header");
        return -2;
    }
    switch (self->magic_number) {
    case 0x4d3cb2a1:
        self->is_nanosec = 1;
    case 0xd4c3b2a1:
        self->is_swapped    = 1;
        self->version_major = bswap_16(self->version_major);
        self->version_minor = bswap_16(self->version_minor);
        self->thiszone      = (int32_t)bswap_32((uint32_t)self->thiszone);
        self->sigfigs       = bswap_32(self->sigfigs);
        self->snaplen       = bswap_32(self->snaplen);
        self->network       = bswap_32(self->network);
        break;
    case 0xa1b2c3d4:
    case 0xa1b23c4d:
        break;
    default:
        lcritical("invalid PCAP header");
        return -2;
    }

    if (self->snaplen > MAX_SNAPLEN) {
        lcritical("too large snaplen (%u)", self->snaplen);
        return -2;
    }

    if (self->version_major != 2 || self->version_minor != 4) {
        lcritical("unsupported PCAP version v%u.%u", self->version_major, self->version_minor);
        return -2;
    }

    /*
     * Translation taken from https://github.com/the-tcpdump-group/libpcap/blob/90543970fd5fbed261d3637f5ec4811d7dde4e49/pcap-common.c#L1212 .
     */
    switch (self->network) {
    case 101:
        self->linktype = DLT_RAW;
        break;
#ifdef DLT_FR
    case 107: /* LINKTYPE_FRELAY */
        self->linktype = DLT_FR;
        break;
#endif
    case 100: /* LINKTYPE_ATM_RFC1483 */
        self->linktype = DLT_ATM_RFC1483;
        break;
    case 102: /* LINKTYPE_SLIP_BSDOS */
        self->linktype = DLT_SLIP_BSDOS;
        break;
    case 103: /* LINKTYPE_PPP_BSDOS */
        self->linktype = DLT_PPP_BSDOS;
        break;
    case 104: /* LINKTYPE_C_HDLC */
        self->linktype = DLT_C_HDLC;
        break;
    case 106: /* LINKTYPE_ATM_CLIP */
        self->linktype = DLT_ATM_CLIP;
        break;
    case 50: /* LINKTYPE_PPP_HDLC */
        self->linktype = DLT_PPP_SERIAL;
        break;
    case 51: /* LINKTYPE_PPP_ETHER */
        self->linktype = DLT_PPP_ETHER;
        break;
    default:
        self->linktype = self->network;
    }

    lfatal_oom(self->buf = malloc(self->snaplen));
    self->prod_pkt.snaplen    = self->snaplen;
    self->prod_pkt.linktype   = self->linktype;
    self->prod_pkt.bytes      = (unsigned char*)self->buf;
    self->prod_pkt.is_swapped = self->is_swapped;

    ldebug("pcap v%u.%u snaplen:%lu %s", self->version_major, self->version_minor, self->snaplen, self->is_swapped ? " swapped" : "");

    return 0;
}

int input_fpcap_open(input_fpcap_t* self, const char* file)
{
    mlassert_self();
    lassert(file, "file is nil");

    if (self->file) {
        lfatal("already opened");
    }

    if (!(self->file = fopen(file, "rb"))) {
        lcritical("fopen(%s) error: %s", file, core_log_errstr(errno));
        return -1;
    }

    return _open(self);
}

int input_fpcap_openfp(input_fpcap_t* self, void* fp)
{
    mlassert_self();

    if (self->file) {
        lfatal("already opened");
    }

    self->file        = fp;
    self->extern_file = 1;

    return _open(self);
}

int input_fpcap_run(input_fpcap_t* self)
{
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } hdr;
    core_object_pcap_t pkt = CORE_OBJECT_PCAP_INIT(0);
    int                ret;
    mlassert_self();

    if (!self->file) {
        lfatal("no PCAP opened");
    }
    if (!self->recv) {
        lfatal("no receiver set");
    }

    pkt.snaplen    = self->snaplen;
    pkt.linktype   = self->linktype;
    pkt.bytes      = (unsigned char*)self->buf;
    pkt.is_swapped = self->is_swapped;

    while ((ret = fread(&hdr, 1, 16, self->file)) == 16) {
        if (self->is_swapped) {
            hdr.ts_sec   = bswap_32(hdr.ts_sec);
            hdr.ts_usec  = bswap_32(hdr.ts_usec);
            hdr.incl_len = bswap_32(hdr.incl_len);
            hdr.orig_len = bswap_32(hdr.orig_len);
        }
        if (hdr.incl_len > self->snaplen) {
            lwarning("invalid packet length, larger then snaplen");
            return -1;
        }
        if (fread(self->buf, 1, hdr.incl_len, self->file) != hdr.incl_len) {
            lwarning("could not read all of packet, aborting");
            return -1;
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
    if (ret) {
        lwarning("could not read next PCAP header, aborting");
        return -1;
    }

    return 0;
}

static const core_object_t* _produce(input_fpcap_t* self)
{
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } hdr;
    int ret;
    mlassert_self();

    if (self->is_broken) {
        lwarning("PCAP is broken, will not read next packet");
        return 0;
    }

    if ((ret = fread(&hdr, 1, 16, self->file)) != 16) {
        if (ret) {
            lwarning("could not read next PCAP header, aborting");
            self->is_broken = 1;
        }
        return 0;
    }

    if (self->is_swapped) {
        hdr.ts_sec   = bswap_32(hdr.ts_sec);
        hdr.ts_usec  = bswap_32(hdr.ts_usec);
        hdr.incl_len = bswap_32(hdr.incl_len);
        hdr.orig_len = bswap_32(hdr.orig_len);
    }
    if (hdr.incl_len > self->snaplen) {
        lwarning("invalid packet length, larger then snaplen");
        self->is_broken = 1;
        return 0;
    }
    if (fread(self->buf, 1, hdr.incl_len, self->file) != hdr.incl_len) {
        lwarning("could not read all of packet, aborting");
        self->is_broken = 1;
        return 0;
    }

    self->pkts++;

    self->prod_pkt.ts.sec = hdr.ts_sec;
    if (self->is_nanosec) {
        self->prod_pkt.ts.nsec = hdr.ts_usec;
    } else {
        self->prod_pkt.ts.nsec = hdr.ts_usec * 1000;
    }
    self->prod_pkt.caplen = hdr.incl_len;
    self->prod_pkt.len    = hdr.orig_len;

    return (core_object_t*)&self->prod_pkt;
}

core_producer_t input_fpcap_producer(input_fpcap_t* self)
{
    mlassert_self();

    if (!self->file) {
        lfatal("no PCAP opened");
    }

    return (core_producer_t)_produce;
}

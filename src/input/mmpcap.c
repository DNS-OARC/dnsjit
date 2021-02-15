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

#include "input/mmpcap.h"
#include "core/assert.h"
#include "core/object/pcap.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
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
#include <pcap/pcap.h>

static core_log_t     _log      = LOG_T_INIT("input.mmpcap");
static input_mmpcap_t _defaults = {
    LOG_T_INIT_OBJ("input.mmpcap"),
    0, 0,
    0, 0, 0,
    CORE_OBJECT_PCAP_INIT(0),
    -1, 0, 0, 0, MAP_FAILED,
    0, 0, 0, 0, 0, 0, 0,
    0
};

core_log_t* input_mmpcap_log()
{
    return &_log;
}

void input_mmpcap_init(input_mmpcap_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void input_mmpcap_destroy(input_mmpcap_t* self)
{
    mlassert_self();

    if (self->buf != MAP_FAILED) {
        munmap(self->buf, self->len);
    }
    if (self->fd > -1) {
        close(self->fd);
    }
}

int input_mmpcap_open(input_mmpcap_t* self, const char* file)
{
    struct stat sb;
    mlassert_self();
    lassert(file, "file is nil");

    if (self->fd != -1) {
        lfatal("already opened");
    }

    if ((self->fd = open(file, O_RDONLY)) < 0) {
        lcritical("open(%s) error %s", file, core_log_errstr(errno));
        return -1;
    }

    if (fstat(self->fd, &sb)) {
        lcritical("stat(%s) error %s", file, core_log_errstr(errno));
        return -1;
    }
    self->len = sb.st_size;

    if ((self->buf = mmap(0, self->len, PROT_READ, MAP_PRIVATE, self->fd, 0)) == MAP_FAILED) {
        lcritical("mmap(%s) error %s", file, core_log_errstr(errno));
        return -1;
    }
    (void)posix_madvise(self->buf, self->len, POSIX_MADV_SEQUENTIAL);

    if (self->len < 24) {
        lcritical("could not read full PCAP header");
        return -2;
    }
    memcpy(&self->magic_number, self->buf, 4);
    memcpy(&self->version_major, self->buf + 4, 2);
    memcpy(&self->version_minor, self->buf + 6, 2);
    memcpy(&self->thiszone, self->buf + 8, 4);
    memcpy(&self->sigfigs, self->buf + 12, 4);
    memcpy(&self->snaplen, self->buf + 16, 4);
    memcpy(&self->network, self->buf + 20, 4);
    self->at = 24;
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

    if (self->version_major != 2 || self->version_minor != 4) {
        lcritical("unsupported PCAP version v%u.%u", self->version_major, self->version_minor);
        return -2;
    }

    /*
     * Translation taken from https://github.com/the-tcpdump-group/libpcap/blob/90543970fd5fbed261d3637f5ec4811d7dde4e49/pcap-common.c#L1212 .
     */
    switch (self->network) {
    case 101: /* LINKTYPE_RAW */
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

    self->prod_pkt.snaplen    = self->snaplen;
    self->prod_pkt.linktype   = self->linktype;
    self->prod_pkt.is_swapped = self->is_swapped;

    ldebug("pcap v%u.%u snaplen:%lu %s", self->version_major, self->version_minor, self->snaplen, self->is_swapped ? " swapped" : "");

    return 0;
}

int input_mmpcap_run(input_mmpcap_t* self)
{
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } hdr;
    core_object_pcap_t pkt = CORE_OBJECT_PCAP_INIT(0);
    mlassert_self();

    if (self->buf == MAP_FAILED) {
        lfatal("no PCAP opened");
    }
    if (!self->recv) {
        lfatal("no receiver set");
    }

    pkt.snaplen    = self->snaplen;
    pkt.linktype   = self->linktype;
    pkt.is_swapped = self->is_swapped;

    while (self->len - self->at > 16) {
        memcpy(&hdr, &self->buf[self->at], 16);
        self->at += 16;
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
        if (self->len - self->at < hdr.incl_len) {
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
        pkt.bytes  = (unsigned char*)&self->buf[self->at];
        pkt.caplen = hdr.incl_len;
        pkt.len    = hdr.orig_len;

        self->recv(self->ctx, (core_object_t*)&pkt);

        self->at += hdr.incl_len;
    }
    if (self->at < self->len) {
        lwarning("could not read next PCAP header, aborting");
        return -1;
    }

    return 0;
}

static const core_object_t* _produce(input_mmpcap_t* self)
{
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } hdr;
    mlassert_self();

    if (self->is_broken) {
        lwarning("PCAP is broken, will not read next packet");
        return 0;
    }

    if (self->len - self->at < 16) {
        if (self->at < self->len) {
            lwarning("could not read next PCAP header, aborting");
            self->is_broken = 1;
        }
        return 0;
    }

    memcpy(&hdr, &self->buf[self->at], 16);
    self->at += 16;
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
    if (self->len - self->at < hdr.incl_len) {
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
    self->prod_pkt.bytes  = (unsigned char*)&self->buf[self->at];
    self->prod_pkt.caplen = hdr.incl_len;
    self->prod_pkt.len    = hdr.orig_len;

    self->at += hdr.incl_len;
    return (core_object_t*)&self->prod_pkt;
}

core_producer_t input_mmpcap_producer(input_mmpcap_t* self)
{
    mlassert_self();

    if (self->buf == MAP_FAILED) {
        lfatal("no PCAP opened");
    }

    return (core_producer_t)_produce;
}

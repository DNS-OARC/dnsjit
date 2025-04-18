/*
 * Copyright (c) 2018-2025 OARC, Inc.
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

#include "input/zmmpcap.h"
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

#ifdef HAVE_LZ4
#include <lz4frame.h>
struct _lz4_ctx {
    LZ4F_dctx*               ctx;
    LZ4F_decompressOptions_t opts;
};
#define lz4 ((struct _lz4_ctx*)self->comp_ctx)
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
struct _zstd_ctx {
    ZSTD_DCtx*     ctx;
    ZSTD_inBuffer  in;
    ZSTD_outBuffer out;
};
#define zstd ((struct _zstd_ctx*)self->comp_ctx)
#endif

#include <zlib.h>
struct _gzip_ctx {
    z_stream strm;
};
#define gzip ((struct _gzip_ctx*)self->comp_ctx)

#ifdef HAVE_LZMA
#include <lzma.h>
struct _lzma_ctx {
    lzma_stream strm;
};
static lzma_stream lzma_stream_init = LZMA_STREAM_INIT;
#define lzma ((struct _lzma_ctx*)self->comp_ctx)
#endif

static core_log_t      _log      = LOG_T_INIT("input.zmmpcap");
static input_zmmpcap_t _defaults = {
    LOG_T_INIT_OBJ("input.zmmpcap"),
    0, 0,
    0, 0, 0,
    CORE_OBJECT_PCAP_INIT(0),
    input_zmmpcap_type_none, 0,
    0, 0, 0, 0,
    -1, 0, 0, 0, MAP_FAILED,
    0, 0, 0, 0, 0, 0, 0,
    0
};

core_log_t* input_zmmpcap_log()
{
    return &_log;
}

void input_zmmpcap_init(input_zmmpcap_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void input_zmmpcap_destroy(input_zmmpcap_t* self)
{
    mlassert_self();

    free(self->out);

    switch (self->compression) {
#ifdef HAVE_LZ4
    case input_zmmpcap_type_lz4: {
        LZ4F_errorCode_t code;

        if (lz4 && lz4->ctx && (code = LZ4F_freeDecompressionContext(lz4->ctx))) {
            lfatal("LZ4F_freeDecompressionContext() failed: %s", LZ4F_getErrorName(code));
        }
        free(lz4);
        break;
    }
#endif
#ifdef HAVE_ZSTD
    case input_zmmpcap_type_zstd:
        if (zstd && zstd->ctx) {
            ZSTD_freeDCtx(zstd->ctx);
        }
        free(zstd);
        break;
#endif
    case input_zmmpcap_type_gzip:
        if (gzip) {
            inflateEnd(&gzip->strm);
        }
        free(gzip);
        break;
#ifdef HAVE_LZMA
    case input_zmmpcap_type_lzma:
        if (lzma) {
            lzma_end(&lzma->strm);
        }
        free(lzma);
        break;
#endif
    default:
        break;
    }

    if (self->map != MAP_FAILED) {
        munmap(self->map, self->len);
    }
    if (self->fd > -1) {
        close(self->fd);
    }
    free(self->buf);
}

static ssize_t _read(input_zmmpcap_t* self, void* dst, size_t len, void** dstp)
{
    switch (self->compression) {
#ifdef HAVE_LZ4
    case input_zmmpcap_type_lz4: {
        size_t need = len;

        if (dstp && self->out_have >= need) {
            *dstp = self->out + self->out_at;
            self->out_have -= need;
            self->out_at += need;
            return len;
        }

        for (;;) {
            if (self->out_have >= need) {
                memcpy(dst, self->out + self->out_at, need);
                self->out_have -= need;
                self->out_at += need;
                return len;
            }

            memcpy(dst, self->out + self->out_at, self->out_have);
            need -= self->out_have;
            dst += self->out_have;

            if (self->at >= self->len) {
                return 0;
            }

            size_t dst_size = self->out_size, src_size = self->len - self->at;
            size_t code = LZ4F_decompress(lz4->ctx, self->out, &dst_size, &self->map[self->at], &src_size, &lz4->opts);
            if (LZ4F_isError(code)) {
                lfatal("LZ4F_decompress() failed: %s", LZ4F_getErrorName(code));
            }

            self->at += src_size;
            self->out_at   = 0;
            self->out_have = dst_size;
        }
    }
#endif
#ifdef HAVE_ZSTD
    case input_zmmpcap_type_zstd: {
        size_t need = len;

        if (dstp && self->out_have >= need) {
            *dstp = self->out + self->out_at;
            self->out_have -= need;
            self->out_at += need;
            return len;
        }

        for (;;) {
            if (self->out_have >= need) {
                memcpy(dst, self->out + self->out_at, need);
                self->out_have -= need;
                self->out_at += need;
                return len;
            }

            memcpy(dst, self->out + self->out_at, self->out_have);
            need -= self->out_have;
            dst += self->out_have;

            if (zstd->in.pos >= zstd->in.size) {
                return 0;
            }

            zstd->out.size = self->out_size;
            zstd->out.pos  = 0;
            size_t code    = ZSTD_decompressStream(zstd->ctx, &zstd->out, &zstd->in);
            if (ZSTD_isError(code)) {
                lfatal("ZSTD_decompressStream() failed: %s", ZSTD_getErrorName(code));
            }

            self->out_have = zstd->out.pos;
            self->out_at   = 0;
        }
    }
#endif
    case input_zmmpcap_type_gzip: {
        size_t need = len;

        if (dstp && self->out_have >= need) {
            *dstp = self->out + self->out_at;
            self->out_have -= need;
            self->out_at += need;
            return len;
        }

        for (;;) {
            if (self->out_have >= need) {
                memcpy(dst, self->out + self->out_at, need);
                self->out_have -= need;
                self->out_at += need;
                return len;
            }

            memcpy(dst, self->out + self->out_at, self->out_have);
            need -= self->out_have;
            dst += self->out_have;

            if (gzip->strm.avail_in <= 0) {
                return 0;
            }

            gzip->strm.next_out  = self->out;
            gzip->strm.avail_out = self->out_size;

            self->out_at = 0;
            int ret      = inflate(&gzip->strm, Z_NO_FLUSH);
            if (ret != Z_OK) {
                if (ret == Z_STREAM_END) {
                    self->out_have = self->out_size - gzip->strm.avail_out;
                    if (self->out_have > 0) {
                        continue;
                    }
                    return 0;
                }
                lfatal("inflate() failed: %d: %s", ret, gzip->strm.msg);
            }

            self->out_have = self->out_size - gzip->strm.avail_out;
        }
    }
#ifdef HAVE_LZMA
    case input_zmmpcap_type_lzma: {
        size_t need = len;

        if (dstp && self->out_have >= need) {
            *dstp = self->out + self->out_at;
            self->out_have -= need;
            self->out_at += need;
            return len;
        }

        lzma_action action = LZMA_RUN;
        for (;;) {
            if (self->out_have >= need) {
                memcpy(dst, self->out + self->out_at, need);
                self->out_have -= need;
                self->out_at += need;
                return len;
            }

            memcpy(dst, self->out + self->out_at, self->out_have);
            need -= self->out_have;
            dst += self->out_have;

            if (lzma->strm.avail_in <= 0) {
                return 0;
            }

            lzma->strm.next_out  = self->out;
            lzma->strm.avail_out = self->out_size;

            self->out_at = 0;
            lzma_ret ret = lzma_code(&lzma->strm, action);
            if (ret != LZMA_OK) {
                if (ret == LZMA_STREAM_END) {
                    self->out_have = self->out_size - lzma->strm.avail_out;
                    if (self->out_have > 0) {
                        continue;
                    }
                    return 0;
                }
                lfatal("lzma_code() failed: %d", ret);
            }

            self->out_have = self->out_size - lzma->strm.avail_out;
        }
    }
#endif
    default:
        return 0;
    }
}

int input_zmmpcap_open(input_zmmpcap_t* self, const char* file)
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

    if ((self->map = mmap(0, self->len, PROT_READ, MAP_PRIVATE, self->fd, 0)) == MAP_FAILED) {
        lcritical("mmap(%s) error %s", file, core_log_errstr(errno));
        return -1;
    }

    switch (self->compression) {
#ifdef HAVE_LZ4
    case input_zmmpcap_type_lz4: {
        LZ4F_errorCode_t code;

        if (lz4 && lz4->ctx && (code = LZ4F_freeDecompressionContext(lz4->ctx))) {
            lfatal("LZ4F_freeDecompressionContext() failed: %s", LZ4F_getErrorName(code));
        }
        free(lz4);
        free(self->out);

        lfatal_oom(self->comp_ctx = calloc(1, sizeof(struct _lz4_ctx)));
        if ((code = LZ4F_createDecompressionContext(&lz4->ctx, LZ4F_VERSION))) {
            lfatal("LZ4F_createDecompressionContext() failed: %s", LZ4F_getErrorName(code));
        }
        lz4->opts.stableDst = 1;

        self->out_size = 256 * 1024;
        lfatal_oom(self->out = malloc(self->out_size));
        break;
    }
#endif
#ifdef HAVE_ZSTD
    case input_zmmpcap_type_zstd:
        if (zstd && zstd->ctx) {
            ZSTD_freeDCtx(zstd->ctx);
        }
        free(zstd);
        free(self->out);

        lfatal_oom(self->comp_ctx = calloc(1, sizeof(struct _zstd_ctx)));
        lfatal_oom(zstd->ctx = ZSTD_createDCtx());
        self->out_size = ZSTD_DStreamOutSize();
        lfatal_oom(self->out = malloc(self->out_size + 1));

        zstd->in.src   = self->map;
        zstd->in.size  = self->len;
        zstd->out.dst  = self->out;
        zstd->out.size = self->out_size;
        break;
#endif
    case input_zmmpcap_type_gzip: {
        if (gzip) {
            inflateEnd(&gzip->strm);
        }
        free(gzip);
        free(self->out);

        lfatal_oom(self->comp_ctx = calloc(1, sizeof(struct _gzip_ctx)));
        int ret = inflateInit2(&gzip->strm, 32);
        if (ret != Z_OK) {
            lcritical("inflateInit() error: %d", ret);
            return -1;
        }

        self->out_size = 256 * 1024;
        lfatal_oom(self->out = malloc(self->out_size));

        gzip->strm.next_in  = self->map;
        gzip->strm.avail_in = self->len;
        break;
    }
#ifdef HAVE_LZMA
    case input_zmmpcap_type_lzma: {
        if (lzma) {
            lzma_end(&lzma->strm);
        }
        free(lzma);
        free(self->out);

        lfatal_oom(self->comp_ctx = calloc(1, sizeof(struct _lzma_ctx)));
        lzma->strm   = lzma_stream_init;
        lzma_ret ret = lzma_stream_decoder(&lzma->strm, UINT64_MAX, LZMA_CONCATENATED);
        if (ret != LZMA_OK) {
            lcritical("lzma_stream_decoder() error: %d", ret);
            return -1;
        }

        self->out_size = 256 * 1024;
        lfatal_oom(self->out = malloc(self->out_size));

        lzma->strm.next_in  = self->map;
        lzma->strm.avail_in = self->len;
        break;
    }
#endif
    default:
        lcritical("no support for selected compression");
        return -2;
    }

    if (_read(self, &self->magic_number, 4, 0) != 4
        || _read(self, &self->version_major, 2, 0) != 2
        || _read(self, &self->version_minor, 2, 0) != 2
        || _read(self, &self->thiszone, 4, 0) != 4
        || _read(self, &self->sigfigs, 4, 0) != 4
        || _read(self, &self->snaplen, 4, 0) != 4
        || _read(self, &self->network, 4, 0) != 4) {
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

    free(self->buf);
    lfatal_oom(self->buf = malloc(self->snaplen));
    self->prod_pkt.snaplen    = self->snaplen;
    self->prod_pkt.linktype   = self->linktype;
    self->prod_pkt.is_swapped = self->is_swapped;

    ldebug("pcap v%u.%u snaplen:%lu %s", self->version_major, self->version_minor, self->snaplen, self->is_swapped ? " swapped" : "");

    return 0;
}

int input_zmmpcap_run(input_zmmpcap_t* self)
{
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } hdr;
    int                ret;
    core_object_pcap_t pkt = CORE_OBJECT_PCAP_INIT(0);
    mlassert_self();

    if (self->map == MAP_FAILED) {
        lfatal("no PCAP opened");
    }
    if (!self->recv) {
        lfatal("no receiver set");
    }

    pkt.snaplen    = self->snaplen;
    pkt.linktype   = self->linktype;
    pkt.is_swapped = self->is_swapped;

    while ((ret = _read(self, &hdr, 16, 0)) == 16) {
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
        pkt.bytes = (unsigned char*)self->buf;
        if (_read(self, self->buf, hdr.incl_len, (void**)&pkt.bytes) != hdr.incl_len) {
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

static const core_object_t* _produce(input_zmmpcap_t* self)
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

    if ((ret = _read(self, &hdr, 16, 0)) != 16) {
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
    self->prod_pkt.bytes = (unsigned char*)self->buf;
    if (_read(self, self->buf, hdr.incl_len, (void**)&self->prod_pkt.bytes) != hdr.incl_len) {
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

core_producer_t input_zmmpcap_producer(input_zmmpcap_t* self)
{
    mlassert_self();

    if (self->map == MAP_FAILED) {
        lfatal("no PCAP opened");
    }

    return (core_producer_t)_produce;
}

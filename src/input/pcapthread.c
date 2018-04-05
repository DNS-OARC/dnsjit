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

#include "input/pcapthread.h"
#include "core/tracking.h"
#include "core/object/packet.h"

#include <string.h>

static core_log_t         _log      = LOG_T_INIT("input.pcapthread");
static input_pcapthread_t _defaults = {
    LOG_T_INIT_OBJ("input.pcapthread"),
    0, 0,
    0, 0, 0,
    { 0, 0 }, { 0, 0 },
    0, 0, 0, 0,
    PCAP_THREAD_OK,
    0, 1
};

core_log_t* input_pcapthread_log()
{
    return &_log;
}

static void _udp(u_char* user, const pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    input_pcapthread_t*  self = (input_pcapthread_t*)user;
    core_object_packet_t pkt  = CORE_OBJECT_PACKET_INIT(0);

    self->pkts++;

    if (self->only_queries) {
        if (length < 3) {
            self->drop++;
            return;
        }
        if (payload[2] & 0x80) {
            self->ignore++;
            return;
        }

        self->queries++;
    }

    if (packet->have_iphdr) {
        pkt.src_addr = &packet->iphdr.ip_src;
        pkt.dst_addr = &packet->iphdr.ip_dst;
        pkt.is_ipv6  = 0;
    } else if (packet->have_ip6hdr) {
        pkt.src_addr = &packet->ip6hdr.ip6_src;
        pkt.dst_addr = &packet->ip6hdr.ip6_dst;
        pkt.is_ipv6  = 1;
    }

    for (; packet; packet = packet->prevpkt) {
        if (packet->have_pkthdr) {
            pkt.ts.sec  = packet->pkthdr.ts.tv_sec;
            pkt.ts.nsec = packet->pkthdr.ts.tv_usec * 1000;
            break;
        }
    }
    if (!packet) {
        self->drop++;
        return;
    }

    pkt.src_id = self->src_id;
    if (!self->qr_id) {
        /* 0 is error */
        self->qr_id++;
    }
    pkt.qr_id = self->qr_id++;

    pkt.is_udp  = 1;
    pkt.is_tcp  = 0;
    pkt.sport   = packet->udphdr.uh_sport;
    pkt.dport   = packet->udphdr.uh_dport;
    pkt.payload = payload;
    pkt.len     = length;

    self->recv(self->ctx, (core_object_t*)&pkt);
}

static void _tcp(u_char* user, const pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    input_pcapthread_t*  self = (input_pcapthread_t*)user;
    core_object_packet_t pkt  = CORE_OBJECT_PACKET_INIT(0);

    self->pkts++;

    // TODO:
    // - include DNS length
    // - track queries if length comes in its own packet
    // - keep length in raw if sent in same packet
    if (length < 3) {
        self->drop++;
        return;
    }
    payload += 2;
    length -= 2;

    if (self->only_queries) {
        if (length < 3) {
            self->drop++;
            return;
        }
        if (payload[2] & 0x80) {
            self->ignore++;
            return;
        }

        self->queries++;
    }

    if (packet->have_iphdr) {
        pkt.src_addr = &packet->iphdr.ip_src;
        pkt.dst_addr = &packet->iphdr.ip_dst;
        pkt.is_ipv6  = 0;
    } else if (packet->have_ip6hdr) {
        pkt.src_addr = &packet->ip6hdr.ip6_src;
        pkt.dst_addr = &packet->ip6hdr.ip6_dst;
        pkt.is_ipv6  = 1;
    }

    for (; packet; packet = packet->prevpkt) {
        if (packet->have_pkthdr) {
            pkt.ts.sec  = packet->pkthdr.ts.tv_sec;
            pkt.ts.nsec = packet->pkthdr.ts.tv_usec * 1000;
            break;
        }
    }
    if (!packet) {
        self->drop++;
        return;
    }

    pkt.src_id = self->src_id;
    if (!self->qr_id) {
        /* 0 is error */
        self->qr_id++;
    }
    pkt.qr_id = self->qr_id++;

    pkt.is_udp  = 0;
    pkt.is_tcp  = 1;
    pkt.sport   = packet->udphdr.uh_sport;
    pkt.dport   = packet->udphdr.uh_dport;
    pkt.payload = payload;
    pkt.len     = length;

    self->recv(self->ctx, (core_object_t*)&pkt);
}

int input_pcapthread_init(input_pcapthread_t* self)
{
    if (!self) {
        return 1;
    }

    *self        = _defaults;
    self->src_id = core_tracking_src_id();

    ldebug("init");

    if (!(self->pt = pcap_thread_create())) {
        return 1;
    }

    if ((self->err = pcap_thread_set_use_threads(self->pt, 1))
        || (self->err = pcap_thread_set_use_layers(self->pt, 1))
        || (self->err = pcap_thread_set_callback_udp(self->pt, _udp))
        || (self->err = pcap_thread_set_callback_tcp(self->pt, _tcp))
        || (self->err = pcap_thread_set_snaplen(self->pt, 64 * 1024))
        || (self->err = pcap_thread_set_buffer_size(self->pt, 4 * 1024 * 1024))
        || (self->err = pcap_thread_set_queue_mode(self->pt, PCAP_THREAD_QUEUE_MODE_DIRECT))) {
        return 1;
    }
    self->setup_ok = 1;

    return 0;
}

int input_pcapthread_destroy(input_pcapthread_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    pcap_thread_free(self->pt);

    return 0;
}

int input_pcapthread_open(input_pcapthread_t* self, const char* device)
{
    if (!self || !self->setup_ok) {
        return 1;
    }

    ldebug("open %s", device);

    if ((self->err = pcap_thread_open(self->pt, device, (void*)self)) != PCAP_THREAD_OK) {
        return 1;
    }

    return 0;
}

int input_pcapthread_open_offline(input_pcapthread_t* self, const char* file)
{
    if (!self || !self->setup_ok || !file) {
        return 1;
    }

    ldebug("open_offline %s", file);

    if ((self->err = pcap_thread_open_offline(self->pt, file, (void*)self)) != PCAP_THREAD_OK) {
        return 1;
    }

    return 0;
}

int input_pcapthread_run(input_pcapthread_t* self)
{
    struct timespec ts, te;
    if (!self || !self->setup_ok || !self->recv) {
        return 1;
    }

    ldebug("run");

    clock_gettime(CLOCK_MONOTONIC, &ts);
    if ((self->err = pcap_thread_run(self->pt)) != PCAP_THREAD_OK) {
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &te);

    self->ts.sec  = ts.tv_sec;
    self->ts.nsec = ts.tv_nsec;
    self->te.sec  = te.tv_sec;
    self->te.nsec = te.tv_nsec;

    return 0;
}

int input_pcapthread_next(input_pcapthread_t* self)
{
    if (!self || !self->setup_ok || !self->recv) {
        return 1;
    }

    ldebug("next");

    if ((self->err = pcap_thread_next(self->pt)) != PCAP_THREAD_OK) {
        return 1;
    }

    return 0;
}

const char* input_pcapthread_errbuf(input_pcapthread_t* self)
{
    if (!self || !self->setup_ok) {
        return 0;
    }

    return pcap_thread_errbuf(self->pt);
}

const char* input_pcapthread_strerr(int err)
{
    return pcap_thread_strerr(err);
}

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
#include "input/pcap.h"

#include "omg-dns/omg_dns.h"

static log_t        _log      = LOG_T_INIT("input.pcap");
static input_pcap_t _defaults = {
    LOG_T_INIT_OBJ("input.pcap"),
    0, 0,
    0, 0, 0,
    { 0, 0 }, { 0, 0 },
    0, 0, 0, 0,
    PCAP_THREAD_OK
};

log_t* input_pcap_log()
{
    return &_log;
}

static void _udp(u_char* user, const pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    input_pcap_t*               self = (input_pcap_t*)user;
    query_t*                    q;
    const pcap_thread_packet_t* p;
    omg_dns_t                   dns = OMG_DNS_T_INIT;

    self->pkts++;

    if (self->only_queries) {
        if (omg_dns_parse_header(&dns, payload, length)) {
            self->drop++;
            return;
        }
        if (!omg_dns_have_qr(&dns) || omg_dns_qr(&dns)) {
            self->ignore++;
            return;
        }

        self->queries++;
    }

    if (!(q = query_new())) {
        self->drop++;
        return;
    }
    if (packet->have_iphdr) {
        if (query_set_src(q, AF_INET, &packet->iphdr.ip_src, sizeof(packet->iphdr.ip_src))
            || query_set_dst(q, AF_INET, &packet->iphdr.ip_dst, sizeof(packet->iphdr.ip_dst))) {
            query_free(q);
            self->drop++;
            return;
        }
    } else if (packet->have_ip6hdr) {
        if (query_set_src(q, AF_INET6, &packet->ip6hdr.ip6_src, sizeof(packet->ip6hdr.ip6_src))
            || query_set_dst(q, AF_INET6, &packet->ip6hdr.ip6_dst, sizeof(packet->ip6hdr.ip6_dst))) {
            query_free(q);
            self->drop++;
            return;
        }
    }
    if (!packet->have_udphdr) {
        query_free(q);
        self->drop++;
        return;
    }
    q->is_udp = 1;
    q->sport  = packet->udphdr.uh_sport;
    q->dport  = packet->udphdr.uh_dport;
    for (p = packet; p; p = p->prevpkt) {
        if (p->have_pkthdr) {
            q->ts.sec  = p->pkthdr.ts.tv_sec;
            q->ts.nsec = p->pkthdr.ts.tv_usec * 1000;
            break;
        }
    }
    if (!p) {
        query_free(q);
        self->drop++;
        return;
    }
    if (query_set_raw(q, (const char*)payload, length)) {
        query_free(q);
        self->drop++;
        return;
    }
    if (self->only_queries && query_set_parsed_header(q, dns)) {
        query_free(q);
        self->drop++;
        return;
    }

    self->recv(self->robj, q);
}

static void _tcp(u_char* user, const pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    input_pcap_t*               self = (input_pcap_t*)user;
    query_t*                    q;
    const pcap_thread_packet_t* p;
    omg_dns_t                   dns = OMG_DNS_T_INIT;

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
        if (omg_dns_parse_header(&dns, payload, length)) {
            self->drop++;
            return;
        }
        if (!omg_dns_have_qr(&dns) || omg_dns_qr(&dns)) {
            self->ignore++;
            return;
        }

        self->queries++;
    }

    if (!(q = query_new())) {
        self->drop++;
        return;
    }
    if (packet->have_iphdr) {
        if (query_set_src(q, AF_INET, &packet->iphdr.ip_src, sizeof(packet->iphdr.ip_src))
            || query_set_dst(q, AF_INET, &packet->iphdr.ip_dst, sizeof(packet->iphdr.ip_dst))) {
            query_free(q);
            self->drop++;
            return;
        }
    } else if (packet->have_ip6hdr) {
        if (query_set_src(q, AF_INET6, &packet->ip6hdr.ip6_src, sizeof(packet->ip6hdr.ip6_src))
            || query_set_dst(q, AF_INET6, &packet->ip6hdr.ip6_dst, sizeof(packet->ip6hdr.ip6_dst))) {
            query_free(q);
            self->drop++;
            return;
        }
    }
    if (!packet->have_tcphdr) {
        query_free(q);
        self->drop++;
        return;
    }
    q->is_tcp = 1;
    q->sport  = packet->tcphdr.th_sport;
    q->dport  = packet->tcphdr.th_dport;
    for (p = packet; p; p = p->prevpkt) {
        if (p->have_pkthdr) {
            q->ts.sec  = p->pkthdr.ts.tv_sec;
            q->ts.nsec = p->pkthdr.ts.tv_usec * 1000;
            break;
        }
    }
    if (!p) {
        query_free(q);
        self->drop++;
        return;
    }
    if (query_set_raw(q, (const char*)payload, length)) {
        query_free(q);
        self->drop++;
        return;
    }
    if (self->only_queries && query_set_parsed_header(q, dns)) {
        query_free(q);
        self->drop++;
        return;
    }

    self->recv(self->robj, q);
}

int input_pcap_init(input_pcap_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

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

int input_pcap_destroy(input_pcap_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    pcap_thread_free(self->pt);

    return 0;
}

int input_pcap_open(input_pcap_t* self, const char* device)
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

int input_pcap_open_offline(input_pcap_t* self, const char* file)
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

int input_pcap_run(input_pcap_t* self)
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

int input_pcap_next(input_pcap_t* self)
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

const char* input_pcap_errbuf(input_pcap_t* self)
{
    if (!self || !self->setup_ok) {
        return 0;
    }

    return pcap_thread_errbuf(self->pt);
}

const char* input_pcap_strerr(int err)
{
    return pcap_thread_strerr(err);
}

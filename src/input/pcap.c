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

#include "input/pcap.h"
#include "core/object/pcap.h"

static core_log_t   _log      = LOG_T_INIT("input.pcap");
static input_pcap_t _defaults = {
    LOG_T_INIT_OBJ("input.pcap"),
    0, 0,
    0,
    CORE_OBJECT_PCAP_INIT(0),
    0, 0,
    0, 0
};

core_log_t* input_pcap_log()
{
    return &_log;
}

int input_pcap_init(input_pcap_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    return 0;
}

int input_pcap_destroy(input_pcap_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    if (self->pcap) {
        pcap_close(self->pcap);
    }

    return 0;
}

int input_pcap_open_offline(input_pcap_t* self, const char* file)
{
    if (!self || !file) {
        return 1;
    }

    if (self->pcap) {
        pcap_close(self->pcap);
    }

    if (!(self->pcap = pcap_open_offline(file, 0))) {
        return 1;
    }

    self->snaplen    = pcap_snapshot(self->pcap);
    self->linktype   = pcap_datalink(self->pcap);
    self->is_swapped = pcap_is_swapped(self->pcap);

    self->prod_pkt.snaplen    = self->snaplen;
    self->prod_pkt.linktype   = self->linktype;
    self->prod_pkt.is_swapped = self->is_swapped;

    return 0;
}

static void _handler(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes)
{
    input_pcap_t*      self = (input_pcap_t*)user;
    core_object_pcap_t pkt  = CORE_OBJECT_PCAP_INIT(0);

    if (!self || !h || !bytes) {
        return;
    }

    self->pkts++;

    pkt.snaplen    = self->snaplen;
    pkt.linktype   = self->linktype;
    pkt.ts.sec     = h->ts.tv_sec;
    pkt.ts.nsec    = h->ts.tv_usec * 1000;
    pkt.caplen     = h->caplen;
    pkt.len        = h->len;
    pkt.bytes      = bytes;
    pkt.is_swapped = self->is_swapped;

    self->recv(self->ctx, (core_object_t*)&pkt);
}

int input_pcap_loop(input_pcap_t* self, int cnt)
{
    if (!self || !self->pcap || !self->recv) {
        return -1;
    }

    return pcap_loop(self->pcap, cnt, _handler, (void*)self);
}

int input_pcap_dispatch(input_pcap_t* self, int cnt)
{
    if (!self || !self->pcap || !self->recv) {
        return -1;
    }

    return pcap_dispatch(self->pcap, cnt, _handler, (void*)self);
}

static const core_object_t* _produce(void* ctx)
{
    input_pcap_t*       self = (input_pcap_t*)ctx;
    struct pcap_pkthdr* h;
    const u_char*       bytes;
    int                 ret = 0;

    if (!self || !self->pcap) {
        return 0;
    }

    while (!(ret = pcap_next_ex(self->pcap, &h, &bytes)))
        ;
    if (ret == 1 && h && bytes) {
        self->prod_pkt.ts.sec  = h->ts.tv_sec;
        self->prod_pkt.ts.nsec = h->ts.tv_usec * 1000;
        self->prod_pkt.caplen  = h->caplen;
        self->prod_pkt.len     = h->len;
        self->prod_pkt.bytes   = bytes;
        return (core_object_t*)&self->prod_pkt;
    }

    return 0;
}

core_producer_t input_pcap_producer()
{
    return _produce;
}

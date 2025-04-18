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

#include "output/pcap.h"
#include "core/assert.h"
#include "core/object/pcap.h"

static core_log_t    _log      = LOG_T_INIT("output.pcap");
static output_pcap_t _defaults = {
    LOG_T_INIT_OBJ("output.pcap"),
    0, 0
};

core_log_t* output_pcap_log()
{
    return &_log;
}

void output_pcap_init(output_pcap_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void output_pcap_destroy(output_pcap_t* self)
{
    mlassert_self();
}

int output_pcap_open(output_pcap_t* self, const char* file, int linktype, int snaplen)
{
    mlassert_self();
    if (self->dumper) {
        lfatal("PCAP already opened");
    }

    if (!(self->pcap = pcap_open_dead(linktype, snaplen))) {
        lcritical("pcap_open_dead() failed");
        return -1;
    }

    if (!(self->dumper = pcap_dump_open(self->pcap, file))) {
        lcritical("pcap_dump_open() error: %s", pcap_geterr(self->pcap));
        pcap_close(self->pcap);
        self->pcap = 0;
        return -1;
    }

    return 0;
}

void output_pcap_close(output_pcap_t* self)
{
    mlassert_self();
    if (self->dumper) {
        pcap_dump_close(self->dumper);
        self->dumper = 0;
    }
    if (self->pcap) {
        pcap_close(self->pcap);
        self->pcap = 0;
    }
}

int output_pcap_have_errors(output_pcap_t* self)
{
    mlassert_self();
    if (self->dumper) {
        return ferror(pcap_dump_file(self->dumper));
    }
    return 0;
}

static void _receive(output_pcap_t* self, const core_object_t* obj)
{
    struct pcap_pkthdr hdr;
    mlassert_self();

    while (obj) {
        if (obj->obj_type == CORE_OBJECT_PCAP) {
            hdr.ts.tv_sec  = ((const core_object_pcap_t*)obj)->ts.sec;
            hdr.ts.tv_usec = ((const core_object_pcap_t*)obj)->ts.nsec / 1000;
            hdr.caplen     = ((const core_object_pcap_t*)obj)->caplen;
            hdr.len        = ((const core_object_pcap_t*)obj)->len;

            pcap_dump((void*)self->dumper, &hdr, ((const core_object_pcap_t*)obj)->bytes);
            return;
        }
        obj = obj->obj_prev;
    }
}

core_receiver_t output_pcap_receiver(output_pcap_t* self)
{
    if (!self->dumper) {
        lfatal("PCAP not opened");
    }

    return (core_receiver_t)_receive;
}

/*
 * Copyright (c) 2018-2023, OARC, Inc.
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

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")
//lua:require("dnsjit.core.producer_h")
//lua:require("dnsjit.core.object.pcap_h")

typedef struct input_mmpcap {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;

    uint8_t is_swapped;
    uint8_t is_nanosec;
    uint8_t is_broken;

    core_object_pcap_t prod_pkt;

    int      fd;
    size_t   len, at;
    size_t   pkts;
    uint8_t* buf;

    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;

    uint32_t linktype;
} input_mmpcap_t;

core_log_t* input_mmpcap_log();

void input_mmpcap_init(input_mmpcap_t* self);
void input_mmpcap_destroy(input_mmpcap_t* self);
int  input_mmpcap_open(input_mmpcap_t* self, const char* file);
int  input_mmpcap_run(input_mmpcap_t* self);

core_producer_t input_mmpcap_producer(input_mmpcap_t* self);

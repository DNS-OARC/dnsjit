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

#if 0
typedef struct pcap {} pcap_t;
#endif

// lua:require("dnsjit.core.log")
// lua:require("dnsjit.core.receiver_h")
// lua:require("dnsjit.core.producer_h")
// lua:require("dnsjit.core.object.pcap_h")

typedef struct input_pcap {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;

    uint8_t is_swapped;

    core_object_pcap_t prod_pkt;

    pcap_t* pcap;
    size_t  pkts;

    size_t   snaplen;
    uint32_t linktype;
} input_pcap_t;

core_log_t* input_pcap_log();

void input_pcap_init(input_pcap_t* self);
void input_pcap_destroy(input_pcap_t* self);
int  input_pcap_create(input_pcap_t* self, const char* source);
int  input_pcap_activate(input_pcap_t* self);
int  input_pcap_open_offline(input_pcap_t* self, const char* file);
int  input_pcap_loop(input_pcap_t* self, int cnt);
int  input_pcap_dispatch(input_pcap_t* self, int cnt);

core_producer_t input_pcap_producer(input_pcap_t* self);

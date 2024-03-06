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

// lua:require("dnsjit.core.log")
// lua:require("dnsjit.core.receiver_h")
// lua:require("dnsjit.core.producer_h")
// lua:require("dnsjit.core.object.pcap_h")

typedef enum input_zpcap_type {
    input_zpcap_type_none,
    input_zpcap_type_lz4,
    input_zpcap_type_zstd
} input_zpcap_type_t;

typedef struct input_zpcap {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;

    uint8_t is_swapped;
    uint8_t is_nanosec;
    uint8_t is_broken;

    core_object_pcap_t prod_pkt;

    input_zpcap_type_t compression;
    void*              comp_ctx;

    void * in, *out;
    size_t in_size, out_size;
    size_t in_have, out_have;
    size_t in_at, out_at;

    void*    file;
    int      extern_file, use_fadvise;
    size_t   pkts;
    uint8_t* buf;
    size_t   buf_size;

    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;

    uint32_t linktype;
} input_zpcap_t;

core_log_t* input_zpcap_log();

void input_zpcap_init(input_zpcap_t* self);
void input_zpcap_destroy(input_zpcap_t* self);
int  input_zpcap_open(input_zpcap_t* self, const char* file);
int  input_zpcap_openfp(input_zpcap_t* self, void* fp);
int  input_zpcap_run(input_zpcap_t* self);
int  input_zpcap_have_support(input_zpcap_t* self);

core_producer_t input_zpcap_producer(input_zpcap_t* self);

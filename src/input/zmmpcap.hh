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

// lua:require("dnsjit.core.log")
// lua:require("dnsjit.core.receiver_h")
// lua:require("dnsjit.core.producer_h")
// lua:require("dnsjit.core.object.pcap_h")

typedef enum input_zmmpcap_type {
    input_zmmpcap_type_none,
    input_zmmpcap_type_lz4,
    input_zmmpcap_type_zstd,
    input_zmmpcap_type_gzip,
    input_zmmpcap_type_lzma
} input_zmmpcap_type_t;

typedef struct input_zmmpcap {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;

    uint8_t is_swapped;
    uint8_t is_nanosec;
    uint8_t is_broken;

    core_object_pcap_t prod_pkt;

    input_zmmpcap_type_t compression;
    void*                comp_ctx;

    void*  out;
    size_t out_size;
    size_t out_have;
    size_t out_at;

    int      fd;
    size_t   len, at;
    size_t   pkts;
    uint8_t *map, *buf;

    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;

    uint32_t linktype;
} input_zmmpcap_t;

core_log_t* input_zmmpcap_log();

void input_zmmpcap_init(input_zmmpcap_t* self);
void input_zmmpcap_destroy(input_zmmpcap_t* self);
int  input_zmmpcap_open(input_zmmpcap_t* self, const char* file);
int  input_zmmpcap_run(input_zmmpcap_t* self);
int  input_zmmpcap_have_support(input_zmmpcap_t* self);

core_producer_t input_zmmpcap_producer(input_zmmpcap_t* self);

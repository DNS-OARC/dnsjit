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

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")
//lua:require("dnsjit.core.timespec_h")

typedef struct input_fpcap {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;

    unsigned short is_swapped : 1;
    unsigned short is_nanosec : 1;

    void*           file;
    core_timespec_t ts, te;
    size_t          pkts;
    uint8_t*        buf;

    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} input_fpcap_t;

core_log_t* input_fpcap_log();

int input_fpcap_init(input_fpcap_t* self);
int input_fpcap_destroy(input_fpcap_t* self);
int input_fpcap_open(input_fpcap_t* self, const char* file);
int input_fpcap_run(input_fpcap_t* self);

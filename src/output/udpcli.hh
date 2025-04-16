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

// lua:require("dnsjit.core.compat_h")
// lua:require("dnsjit.core.log")
// lua:require("dnsjit.core.receiver_h")
// lua:require("dnsjit.core.producer_h")
// lua:require("dnsjit.core.object.payload_h")
// lua:require("dnsjit.core.timespec_h")

typedef struct output_udpcli {
    core_log_t _log;
    size_t     pkts, errs;
    int        fd;

    struct sockaddr_storage addr;
    size_t                  addr_len;

    uint8_t               recvbuf[4 * 1024];
    core_object_payload_t pkt;
    size_t                pkts_recv;

    core_timespec_t timeout;
    int8_t          blocking;
} output_udpcli_t;

core_log_t* output_udpcli_log();

void output_udpcli_init(output_udpcli_t* self);
void output_udpcli_destroy(output_udpcli_t* self);
int  output_udpcli_connect(output_udpcli_t* self, const char* host, const char* port);
int  output_udpcli_nonblocking(output_udpcli_t* self);
int  output_udpcli_set_nonblocking(output_udpcli_t* self, int nonblocking);

core_receiver_t output_udpcli_receiver(output_udpcli_t* self);
core_producer_t output_udpcli_producer(output_udpcli_t* self);

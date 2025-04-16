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

typedef enum output_dnscli_mode {
    OUTPUT_DNSCLI_MODE_NONE        = 0,
    OUTPUT_DNSCLI_MODE_OPTIONS     = 0xf,
    OUTPUT_DNSCLI_MODE_NONBLOCKING = 0x1,
    OUTPUT_DNSCLI_MODE_MODES       = 0xf0,
    OUTPUT_DNSCLI_MODE_UDP         = 0x10,
    OUTPUT_DNSCLI_MODE_TCP         = 0x20,
    OUTPUT_DNSCLI_MODE_TLS         = 0x30,
} output_dnscli_mode_t;

typedef struct output_dnscli {
    core_log_t _log;

    output_dnscli_mode_t mode;

    size_t pkts, errs, timeouts;
    int    fd, nonblocking, conn_ok;

    struct pollfd poll;
    int           poll_timeout;

    struct sockaddr_storage addr;
    size_t                  addr_len;

    uint8_t               recvbuf[(64 * 1024) + 2];
    core_object_payload_t pkt;
    uint16_t              dnslen;
    uint8_t               have_dnslen, have_pkt;
    size_t                recv, pkts_recv;

    core_timespec_t timeout;

    gnutls_session_t                 session;
    gnutls_certificate_credentials_t cred;
} output_dnscli_t;

core_log_t* output_dnscli_log();

void           output_dnscli_init(output_dnscli_t* self, output_dnscli_mode_t mode);
void           output_dnscli_destroy(output_dnscli_t* self);
int            output_dnscli_connect(output_dnscli_t* self, const char* host, const char* port);
luajit_ssize_t output_dnscli_send(output_dnscli_t* self, const core_object_t* obj, size_t sent);

core_receiver_t output_dnscli_receiver(output_dnscli_t* self);
core_producer_t output_dnscli_producer(output_dnscli_t* self);

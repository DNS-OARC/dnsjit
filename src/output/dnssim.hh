/*
 * Copyright (c) 2018-2020, CZ.NIC, z.s.p.o.
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

typedef enum output_dnssim_transport {
    OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY,
    OUTPUT_DNSSIM_TRANSPORT_UDP,
    OUTPUT_DNSSIM_TRANSPORT_TCP,
    OUTPUT_DNSSIM_TRANSPORT_TLS
} output_dnssim_transport_t;

typedef struct output_dnssim_stats output_dnssim_stats_t;
struct output_dnssim_stats {
    output_dnssim_stats_t* prev;
    output_dnssim_stats_t* next;

    uint64_t* latency;

    uint64_t since_ms;
    uint64_t until_ms;

    uint64_t requests;
    uint64_t ongoing;
    uint64_t answers;

    /* Number of connections that are open at the end of the stats interval. */
    uint64_t conn_active;

    /* Number of connection handshake attempts during the stats interval. */
    uint64_t conn_handshakes;

    /* Number of connection that have been resumed with TLS session resumption. */
    uint64_t conn_resumed;

    /* Number of timed out connection handshakes during the stats interval. */
    uint64_t conn_handshakes_failed;

    uint64_t rcode_noerror;
    uint64_t rcode_formerr;
    uint64_t rcode_servfail;
    uint64_t rcode_nxdomain;
    uint64_t rcode_notimp;
    uint64_t rcode_refused;
    uint64_t rcode_yxdomain;
    uint64_t rcode_yxrrset;
    uint64_t rcode_nxrrset;
    uint64_t rcode_notauth;
    uint64_t rcode_notzone;
    uint64_t rcode_badvers;
    uint64_t rcode_badkey;
    uint64_t rcode_badtime;
    uint64_t rcode_badmode;
    uint64_t rcode_badname;
    uint64_t rcode_badalg;
    uint64_t rcode_badtrunc;
    uint64_t rcode_badcookie;
    uint64_t rcode_other;
};

typedef struct output_dnssim {
    core_log_t _log;

    uint64_t processed;
    uint64_t discarded;
    uint64_t ongoing;

    output_dnssim_stats_t* stats_sum;
    output_dnssim_stats_t* stats_current;
    output_dnssim_stats_t* stats_first;

    size_t max_clients;
    bool   free_after_use;

    uint64_t timeout_ms;
    uint64_t idle_timeout_ms;
    uint64_t handshake_timeout_ms;
    uint64_t stats_interval_ms;
} output_dnssim_t;

core_log_t* output_dnssim_log();

output_dnssim_t* output_dnssim_new(size_t max_clients);
void output_dnssim_free(output_dnssim_t* self);

void output_dnssim_set_transport(output_dnssim_t* self, output_dnssim_transport_t tr);
int output_dnssim_target(output_dnssim_t* self, const char* ip, uint16_t port);
int output_dnssim_bind(output_dnssim_t* self, const char* ip);
int output_dnssim_run_nowait(output_dnssim_t* self);
void output_dnssim_timeout_ms(output_dnssim_t* self, uint64_t timeout_ms);
void output_dnssim_stats_collect(output_dnssim_t* self, uint64_t interval_ms);
void output_dnssim_stats_finish(output_dnssim_t* self);

core_receiver_t output_dnssim_receiver();

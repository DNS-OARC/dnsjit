/*
 * Copyright (c) 2018-2019, CZ.NIC, z.s.p.o.
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

typedef struct output_dnssim_client {
    // TODO use stats instead
    uint32_t requests;
    uint32_t answers;
    uint32_t noerror;

    float latency_min;
    float latency_mean;
    float latency_max;
} output_dnssim_client_t;

typedef struct output_dnssim_stats output_dnssim_stats_t;
struct output_dnssim_stats {
    output_dnssim_stats_t* prev;
    output_dnssim_stats_t* next;

    uint64_t requests;
    uint64_t ongoing;
    uint64_t answers;

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
    output_dnssim_client_t* client_arr;
    bool free_after_use;

    uint32_t timeout_ms;
} output_dnssim_t;

core_log_t* output_dnssim_log();

output_dnssim_t* output_dnssim_new(size_t max_clients);
void output_dnssim_free(output_dnssim_t* self);

void output_dnssim_set_transport(output_dnssim_t* self, output_dnssim_transport_t tr);
int output_dnssim_target(output_dnssim_t* self, const char* ip, uint16_t port);
int output_dnssim_bind(output_dnssim_t* self, const char* ip);
int output_dnssim_run_nowait(output_dnssim_t* self);
void output_dnssim_stats_collect(output_dnssim_t* self, uint64_t interval_ms);
void output_dnssim_stats_finish(output_dnssim_t* self);

core_receiver_t output_dnssim_receiver();

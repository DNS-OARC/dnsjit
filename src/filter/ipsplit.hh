/*
 * Copyright (c) 2019-2020, CZ.NIC, z.s.p.o.
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

typedef struct filter_ipsplit_recv filter_ipsplit_recv_t;
struct filter_ipsplit_recv {
    filter_ipsplit_recv_t* next;

    core_receiver_t recv;
    void* ctx;

    uint32_t n_clients;  /* Total number of clients assigned to this receiver. */

    uint32_t weight;
};

typedef struct filter_ipsplit {
    core_log_t _log;

    enum {
        IPSPLIT_MODE_SEQUENTIAL = 0,
        IPSPLIT_MODE_RANDOM = 1
    } mode;
    uint64_t discarded;

    filter_ipsplit_recv_t* recv;
} filter_ipsplit_t;

core_log_t* filter_ipsplit_log();

filter_ipsplit_t* filter_ipsplit_new();
void filter_ipsplit_free(filter_ipsplit_t* self);
void filter_ipsplit_add(filter_ipsplit_t* self, core_receiver_t recv, void* ctx, uint32_t weight);
void filter_ipsplit_srand(unsigned int seed);

core_receiver_t filter_ipsplit_receiver(filter_ipsplit_t* self);

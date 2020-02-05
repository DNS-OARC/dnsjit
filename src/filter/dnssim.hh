/*
 * Copyright (c) 2019, CZ.NIC, z.s.p.o.
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

typedef struct filter_dnssim_recv filter_dnssim_recv_t;
struct filter_dnssim_recv {
    filter_dnssim_recv_t* next;

    core_receiver_t recv;
    void* ctx;

    uint32_t client;
};

typedef struct filter_dnssim {
    core_log_t _log;

    uint64_t discarded;

    filter_dnssim_recv_t* recv;
} filter_dnssim_t;

core_log_t* filter_dnssim_log();

filter_dnssim_t* filter_dnssim_new();
void filter_dnssim_free(filter_dnssim_t* self);
void filter_dnssim_add(filter_dnssim_t* self, core_receiver_t recv, void* ctx);

core_receiver_t filter_dnssim_receiver(filter_dnssim_t* self);

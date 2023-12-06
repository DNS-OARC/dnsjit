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

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")

typedef enum filter_split_mode {
    FILTER_SPLIT_MODE_ROUNDROBIN,
    FILTER_SPLIT_MODE_SENDALL
} filter_split_mode_t;

typedef struct filter_split_recv filter_split_recv_t;
struct filter_split_recv {
    filter_split_recv_t* next;
    core_receiver_t      recv;
    void*                ctx;
};

typedef struct filter_split {
    core_log_t           _log;
    filter_split_mode_t  mode;
    filter_split_recv_t* recv_first;
    filter_split_recv_t* recv;
    filter_split_recv_t* recv_last;
} filter_split_t;

core_log_t* filter_split_log();

void filter_split_init(filter_split_t* self);
void filter_split_destroy(filter_split_t* self);
void filter_split_add(filter_split_t* self, core_receiver_t recv, void* ctx);

core_receiver_t filter_split_receiver(filter_split_t* self);

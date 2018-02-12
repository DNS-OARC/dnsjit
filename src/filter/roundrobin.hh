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
typedef struct filter_roundrobin_recv filter_roundrobin_recv_t;
struct filter_roundrobin_recv {
    filter_roundrobin_recv_t* next;
    core_receiver_t           recv;
    void*                     robj;
};
typedef struct filter_roundrobin {
    core_log_t                _log;
    filter_roundrobin_recv_t* recv_list;
    filter_roundrobin_recv_t* recv;
} filter_roundrobin_t;

core_log_t* filter_roundrobin_log();
int filter_roundrobin_init(filter_roundrobin_t* self);
int filter_roundrobin_destroy(filter_roundrobin_t* self);
int filter_roundrobin_add(filter_roundrobin_t* self, core_receiver_t recv, void* robj);

core_receiver_t filter_roundrobin_receiver();

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
typedef struct filter_multicopy_recv filter_multicopy_recv_t;
struct filter_multicopy_recv {
    filter_multicopy_recv_t* next;
    receiver_t               recv;
    void*                    robj;
};
typedef struct filter_multicopy {
    log_t                    _log;
    filter_multicopy_recv_t* recv_list;
} filter_multicopy_t;

log_t* filter_multicopy_log();
int filter_multicopy_init(filter_multicopy_t* self);
int filter_multicopy_destroy(filter_multicopy_t* self);
int filter_multicopy_add(filter_multicopy_t* self, receiver_t recv, void* robj);

receiver_t filter_multicopy_receiver();

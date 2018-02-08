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

#if 0
typedef struct {} pthread_t;
typedef struct {} sllq_t;
#endif
//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")
typedef struct thread {
    log_t          _log;
    unsigned short have_id : 1;
    unsigned short my_queues : 1;
    pthread_t*     id;
    sllq_t*        qin;
    receiver_t     recv;
    void*          robj;
} filter_thread_t;

log_t* filter_thread_log();
int filter_thread_init(filter_thread_t* self);
int filter_thread_destroy(filter_thread_t* self);
int filter_thread_create(filter_thread_t* self, const char* bc, size_t len);
int filter_thread_stop(filter_thread_t* self);
int filter_thread_join(filter_thread_t* self);
receiver_t filter_thread_receiver();

query_t* filter_thread_recv(filter_thread_t* self);
int filter_thread_send(filter_thread_t* self, query_t* q);

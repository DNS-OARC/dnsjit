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
//lua:require("dnsjit.core.log_h")
//lua:require("dnsjit.core.receiver_h")
typedef struct thread {
    log_t          log;
    unsigned short have_id : 1;
    unsigned short my_queues : 1;
    pthread_t*     id;
    sllq_t*        qin;
    receiver_t     recv;
    void*          robj;
} thread_t;

int thread_init(thread_t* self);
int thread_destroy(thread_t* self);
int thread_create(thread_t* self, const char* bc, size_t len);
int thread_stop(thread_t* self);
int thread_join(thread_t* self);
receiver_t thread_receiver();

query_t* thread_recv(thread_t* self);
int thread_send(thread_t* self, query_t* q);

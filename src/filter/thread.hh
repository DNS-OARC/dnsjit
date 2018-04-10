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

//lua:require("dnsjit.core.compat_h")
//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")

typedef struct filter_thread_work {
    core_object_t*  obj;
    pthread_mutex_t mutex;
    pthread_cond_t  read, write;
    uint8_t         writers;
    char            end;
} filter_thread_work_t;

typedef struct filter_thread_recv filter_thread_recv_t;

typedef struct filter_thread {
    core_log_t            _log;
    filter_thread_recv_t* recv;

    filter_thread_work_t* work;
    size_t                works, at;
    unsigned short use_writers : 1;
} filter_thread_t;

struct filter_thread_recv {
    filter_thread_t*      self;
    filter_thread_recv_t* next;
    core_receiver_t       recv;
    void*                 ctx;
    pthread_t             tid;
};

core_log_t* filter_thread_log();

int filter_thread_init(filter_thread_t* self, size_t queue_size);
int filter_thread_destroy(filter_thread_t* self);
int filter_thread_add(filter_thread_t* self, core_receiver_t recv, void* ctx);
int filter_thread_start(filter_thread_t* self);
int filter_thread_stop(filter_thread_t* self);

core_receiver_t filter_thread_receiver(filter_thread_t* self);

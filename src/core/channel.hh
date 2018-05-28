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
//lua:require("dnsjit.core.object")
//lua:require("dnsjit.core.receiver_h")

typedef struct core_channel_item {
    core_object_t*  obj;
    pthread_mutex_t mutex;
    pthread_cond_t  read, write;
    uint8_t         end;
} core_channel_item_t;

typedef struct core_channel {
    core_log_t           _log;
    core_channel_item_t* item;
    size_t               items, at;

    size_t read, read_ends; // TODO move to reader sub module

    core_receiver_t recv;
    void*           ctx;

    void* ring_buf;
    void* ring;
    int   ring_closed;
} core_channel_t;

core_log_t* core_channel_log();

int core_channel_init(core_channel_t* self, size_t size);
int core_channel_destroy(core_channel_t* self);
int core_channel_put(core_channel_t* self, core_object_t* obj);
core_object_t* core_channel_get(core_channel_t* self);
int core_channel_close(core_channel_t* self);
int core_channel_run(core_channel_t* self);

core_receiver_t core_channel_receiver();

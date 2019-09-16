/*
 * Copyright (c) 2018-2019, OARC, Inc.
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

typedef struct core_channel {
    core_log_t        _log;
    ck_ring_buffer_t* ring_buf;
    ck_ring_t         ring;
    int               closed;
    size_t            capacity;

    core_receiver_t recv;
    void*           ctx;
} core_channel_t;

core_log_t* core_channel_log();

void core_channel_init(core_channel_t* self, size_t capacity);
void core_channel_destroy(core_channel_t* self);
void core_channel_put(core_channel_t* self, const void* obj);
int core_channel_try_put(core_channel_t* self, const void* obj);
void* core_channel_get(core_channel_t* self);
void* core_channel_try_get(core_channel_t* self);
int core_channel_size(core_channel_t* self);
bool core_channel_full(core_channel_t* self);
void core_channel_close(core_channel_t* self);

core_receiver_t core_channel_receiver();
void core_channel_run(core_channel_t* self);

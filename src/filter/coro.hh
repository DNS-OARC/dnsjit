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
typedef struct {} lua_State;
#endif

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")

typedef struct filter_coro {
    core_log_t           _log;
    core_receiver_t      recv;
    void*                ctx;
    lua_State*           T;
    const core_object_t* obj;
    int                  done;
} filter_coro_t;

core_log_t* filter_coro_log();

int filter_coro_init(filter_coro_t* self);
int filter_coro_destroy(filter_coro_t* self);

int filter_coro_set_thread(filter_coro_t* self);
int filter_coro_clear_thread(filter_coro_t* self);
int filter_coro_store_thread(lua_State* L);
const core_object_t* filter_coro_get(filter_coro_t* self);

core_receiver_t filter_coro_receiver();

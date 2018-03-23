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

typedef struct filter_lua {
    core_log_t      _log;
    lua_State*      L;
    core_receiver_t recv;
    void*           ctx;
    size_t          args;
} filter_lua_t;

core_log_t* filter_lua_log();

int filter_lua_init(filter_lua_t* self);
int filter_lua_destroy(filter_lua_t* self);
int filter_lua_func(filter_lua_t* self, const char* bc, size_t len);
int filter_lua_push_string(filter_lua_t* self, const char* s, size_t l);
int filter_lua_push_integer(filter_lua_t* self, int i);
int filter_lua_push_double(filter_lua_t* self, double d);

core_receiver_t filter_lua_receiver();

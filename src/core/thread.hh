/*
 * Copyright (c) 2018-2022, OARC, Inc.
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

typedef struct core_thread_item core_thread_item_t;
struct core_thread_item {
    core_thread_item_t* next;
    void*               ptr;
    char *              type, *module;

    char*   str;
    int64_t i64;
};

typedef struct core_thread {
    core_log_t                _log;
    pthread_t                 thr_id;
    core_thread_item_t *      stack, *last;
    const core_thread_item_t* at;

    pthread_mutex_t lock;
    pthread_cond_t  cond;

    char*  bytecode;
    size_t bytecode_len;
} core_thread_t;

core_log_t* core_thread_log();

void                      core_thread_init(core_thread_t* self);
void                      core_thread_destroy(core_thread_t* self);
int                       core_thread_start(core_thread_t* self, const char* bytecode, size_t len);
int                       core_thread_stop(core_thread_t* self);
void                      core_thread_push(core_thread_t* self, void* ptr, const char* type, size_t type_len, const char* module, size_t module_len);
void                      core_thread_push_string(core_thread_t* self, const char* str, size_t len);
void                      core_thread_push_int64(core_thread_t* self, int64_t i64);
const core_thread_item_t* core_thread_pop(core_thread_t* self);

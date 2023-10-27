/*
 * Copyright (c) 2018-2024 OARC, Inc.
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

// lua:require("dnsjit.core.log")
// lua:require("dnsjit.core.receiver_h")

typedef struct output_respdiff {
    core_log_t _log;
    void *     env, *txn, *qdb, *rdb, *meta;
    uint32_t   id;
    size_t     count;
} output_respdiff_t;

core_log_t* output_respdiff_log();
void        output_respdiff_init(output_respdiff_t* self, const char* path, size_t mapsize);
void        output_respdiff_destroy(output_respdiff_t* self);
void        output_respdiff_commit(output_respdiff_t* self, const char* origname, const char* recvname, uint64_t start_time, uint64_t end_time);

core_receiver_t output_respdiff_receiver(output_respdiff_t* self);

/*
 * Copyright (c) 2019, CZ.NIC z.s.p.o.
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
//lua:require("dnsjit.core.producer_h")

typedef struct filter_copy {
    core_log_t _log;

    core_receiver_t recv;
    void*           recv_ctx;

    core_producer_t prod;
    void*           prod_ctx;

    uint64_t copy;
} filter_copy_t;

core_log_t* filter_copy_log();

void filter_copy_init(filter_copy_t* self);
void filter_copy_destroy(filter_copy_t* self);
void filter_copy_set(filter_copy_t* self, int32_t obj_type);
uint64_t filter_copy_get(filter_copy_t* self, int32_t obj_type);

core_receiver_t filter_copy_receiver(filter_copy_t* self);
core_producer_t filter_copy_producer(filter_copy_t* self);

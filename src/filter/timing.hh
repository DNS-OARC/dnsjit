/*
 * Copyright (c) 2018-2025 OARC, Inc.
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
// lua:require("dnsjit.core.producer_h")
// lua:require("dnsjit.core.timespec_h")

typedef struct filter_timing {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;
    enum {
        TIMING_MODE_KEEP     = 0,
        TIMING_MODE_INCREASE = 1,
        TIMING_MODE_REDUCE   = 2,
        TIMING_MODE_MULTIPLY = 3,
        TIMING_MODE_FIXED    = 4,
        TIMING_MODE_REALTIME = 5
    } mode;
    size_t   inc, red, fixed, rt_batch;
    float    mul;
    uint64_t rt_drift;

    core_producer_t prod;
    void*           prod_ctx;
} filter_timing_t;

core_log_t* filter_timing_log();

filter_timing_t* filter_timing_new();
void             filter_timing_free(filter_timing_t* self);

core_receiver_t filter_timing_receiver(filter_timing_t* self);
core_producer_t filter_timing_producer(filter_timing_t* self);

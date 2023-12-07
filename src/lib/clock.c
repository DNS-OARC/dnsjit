/*
 * Copyright (c) 2018-2023, OARC, Inc.
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

#include "config.h"

#include "lib/clock.h"

#include <time.h>

core_timespec_t lib_clock_getres(lib_clock_clkid_t clkid)
{
    struct timespec ts;
    core_timespec_t ret = { 0, 0 };
    clockid_t       clk_id;

    switch (clkid) {
    case LIB_CLOCK_REALTIME:
        clk_id = CLOCK_REALTIME;
        break;
    case LIB_CLOCK_MONOTONIC:
        clk_id = CLOCK_MONOTONIC;
        break;
    default:
        return ret;
    }

    if (!clock_getres(clk_id, &ts)) {
        ret.sec  = ts.tv_sec;
        ret.nsec = ts.tv_nsec;
    }

    return ret;
}

core_timespec_t lib_clock_gettime(lib_clock_clkid_t clkid)
{
    struct timespec ts;
    core_timespec_t ret = { 0, 0 };
    clockid_t       clk_id;

    switch (clkid) {
    case LIB_CLOCK_REALTIME:
        clk_id = CLOCK_REALTIME;
        break;
    case LIB_CLOCK_MONOTONIC:
        clk_id = CLOCK_MONOTONIC;
        break;
    default:
        return ret;
    }

    if (!clock_gettime(clk_id, &ts)) {
        ret.sec  = ts.tv_sec;
        ret.nsec = ts.tv_nsec;
    }

    return ret;
}

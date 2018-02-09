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

#include "config.h"

#include "core/tracking.h"
#include "core/log.h"

#include <pthread.h>

static log_t           _log   = LOG_T_INIT("core.tracking");
static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t        _sid   = 1;

log_t* core_tracking_log()
{
    return &_log;
}

uint64_t core_tracking_new_sid()
{
    uint64_t sid;

    if (pthread_mutex_lock(&_mutex)) {
        return 0;
    }
    if (!_sid) {
        /* 0 is error */
        _sid++;
    }
    sid = _sid++;
    if (pthread_mutex_unlock(&_mutex)) {
        return 0;
    }
    return sid;
}

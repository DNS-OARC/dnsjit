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

static core_log_t      _log          = LOG_T_INIT("core.tracking");
static pthread_mutex_t _src_id_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t        _src_id       = 1;
static pthread_mutex_t _qr_id_mutex  = PTHREAD_MUTEX_INITIALIZER;
static uint64_t        _qr_id        = 1;
static pthread_mutex_t _dst_id_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t        _dst_id       = 1;

core_log_t* core_tracking_log()
{
    return &_log;
}

uint64_t core_tracking_src_id()
{
    uint64_t src_id;

    if (pthread_mutex_lock(&_src_id_mutex)) {
        return 0;
    }
    if (!_src_id) {
        /* 0 is error */
        _src_id++;
    }
    src_id = _src_id++;
    if (pthread_mutex_unlock(&_src_id_mutex)) {
        return 0;
    }
    return src_id;
}

uint64_t core_tracking_qr_id()
{
    uint64_t qr_id;

    if (pthread_mutex_lock(&_qr_id_mutex)) {
        return 0;
    }
    if (!_qr_id) {
        /* 0 is error */
        _qr_id++;
    }
    qr_id = _qr_id++;
    if (pthread_mutex_unlock(&_qr_id_mutex)) {
        return 0;
    }
    return qr_id;
}

uint64_t core_tracking_dst_id()
{
    uint64_t dst_id;

    if (pthread_mutex_lock(&_dst_id_mutex)) {
        return 0;
    }
    if (!_dst_id) {
        /* 0 is error */
        _dst_id++;
    }
    dst_id = _dst_id++;
    if (pthread_mutex_unlock(&_dst_id_mutex)) {
        return 0;
    }
    return dst_id;
}

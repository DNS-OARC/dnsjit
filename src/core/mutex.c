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

#include "core/mutex.h"
#include "core/log.h"

#include <pthread.h>

static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;

int core_mutex_lock()
{
    gldebug("core.mutex.lock()");
    return pthread_mutex_lock(&_mutex);
}

int core_mutex_unlock()
{
    gldebug("core.mutex.unlock()");
    return pthread_mutex_unlock(&_mutex);
}

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

#include "core/log.h"
#include "core/receiver.h"

#ifndef __dnsjit_filter_thread_h
#define __dnsjit_filter_thread_h

#include <stdint.h>
#include <pthread.h>

typedef struct filter_thread_work {
    core_object_t*  obj;
    pthread_mutex_t mutex;
    pthread_cond_t  read, write;
    char            end;
} filter_thread_work_t;

#include "filter/thread.hh"

#endif

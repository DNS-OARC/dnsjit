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

#ifndef __dnsjit_core_log_h
#define __dnsjit_core_log_h

#include <stdlib.h>

#define LOG_T_INIT \
    {              \
        0, 0, 0, 0 \
    }
#include "core/log.hh"

void log_debug(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_info(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_notice(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_warning(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_critical(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_fatal(const log_t* l, const char* file, size_t line, const char* msg, ...);

#define ldebug(msg...) log_debug(&self->log, __FILE__, __LINE__, msg)
#define linfo(msg...) log_info(&self->log, __FILE__, __LINE__, msg)
#define lnotice(msg...) log_notice(&self->log, __FILE__, __LINE__, msg)
#define lwarning(msg...) log_warning(&self->log, __FILE__, __LINE__, msg)
#define lcritical(msg...) log_critical(&self->log, __FILE__, __LINE__, msg)
#define lfatal(msg...) log_fatal(&self->log, __FILE__, __LINE__, msg)

#define gldebug(msg...) log_debug(0, __FILE__, __LINE__, msg)
#define glinfo(msg...) log_info(0, __FILE__, __LINE__, msg)
#define glnotice(msg...) log_notice(0, __FILE__, __LINE__, msg)
#define glwarning(msg...) log_warning(0, __FILE__, __LINE__, msg)
#define glcritical(msg...) log_critical(0, __FILE__, __LINE__, msg)
#define glfatal(msg...) log_fatal(0, __FILE__, __LINE__, msg)

#endif

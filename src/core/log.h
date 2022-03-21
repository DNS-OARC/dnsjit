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

#ifndef __dnsjit_core_log_h
#define __dnsjit_core_log_h

#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

#define LOG_SETTINGS_T_INIT \
    {                       \
        0, 0, 0, 0, 0       \
    }
#define LOG_T_INIT(name)                \
    {                                   \
        name, 0, LOG_SETTINGS_T_INIT, 0 \
    }
#define LOG_T_INIT_OBJ(name)                         \
    {                                                \
        name, 1, LOG_SETTINGS_T_INIT, &_log.settings \
    }

#include <dnsjit/core/log.hh>

#ifdef DNSJIT_NO_LOGGING
#define ldebug(msg...)
#define linfo(msg...)
#define lnotice(msg...)
#define lwarning(msg...)
#define lcritical(msg...)
#define lpdebug(msg...)
#define lpinfo(msg...)
#define lpnotice(msg...)
#define lpwarning(msg...)
#define lpcritical(msg...)
#define mldebug(msg...)
#define mlinfo(msg...)
#define mlnotice(msg...)
#define mlwarning(msg...)
#define mlcritical(msg...)
#define gldebug(msg...)
#define glinfo(msg...)
#define glnotice(msg...)
#define glwarning(msg...)
#define glcritical(msg...)
#else
#define ldebug(msg...) core_log_debug(&self->_log, __FILE__, __LINE__, msg)
#define linfo(msg...) core_log_info(&self->_log, __FILE__, __LINE__, msg)
#define lnotice(msg...) core_log_notice(&self->_log, __FILE__, __LINE__, msg)
#define lwarning(msg...) core_log_warning(&self->_log, __FILE__, __LINE__, msg)
#define lcritical(msg...) core_log_critical(&self->_log, __FILE__, __LINE__, msg)
#define lpdebug(msg...) core_log_debug(self->_log, __FILE__, __LINE__, msg)
#define lpinfo(msg...) core_log_info(self->_log, __FILE__, __LINE__, msg)
#define lpnotice(msg...) core_log_notice(self->_log, __FILE__, __LINE__, msg)
#define lpwarning(msg...) core_log_warning(self->_log, __FILE__, __LINE__, msg)
#define lpcritical(msg...) core_log_critical(self->_log, __FILE__, __LINE__, msg)
#define mldebug(msg...) core_log_debug(&_log, __FILE__, __LINE__, msg)
#define mlinfo(msg...) core_log_info(&_log, __FILE__, __LINE__, msg)
#define mlnotice(msg...) core_log_notice(&_log, __FILE__, __LINE__, msg)
#define mlwarning(msg...) core_log_warning(&_log, __FILE__, __LINE__, msg)
#define mlcritical(msg...) core_log_critical(&_log, __FILE__, __LINE__, msg)
#define gldebug(msg...) core_log_debug(0, __FILE__, __LINE__, msg)
#define glinfo(msg...) core_log_info(0, __FILE__, __LINE__, msg)
#define glnotice(msg...) core_log_notice(0, __FILE__, __LINE__, msg)
#define glwarning(msg...) core_log_warning(0, __FILE__, __LINE__, msg)
#define glcritical(msg...) core_log_critical(0, __FILE__, __LINE__, msg)
#endif

#define lfatal(msg...) core_log_fatal(&self->_log, __FILE__, __LINE__, msg)
#define lpfatal(msg...) core_log_fatal(self->_log, __FILE__, __LINE__, msg)
#define mlfatal(msg...) core_log_fatal(&_log, __FILE__, __LINE__, msg)
#define glfatal(msg...) core_log_fatal(0, __FILE__, __LINE__, msg)

#define lfatal_oom(expression) \
    if (!(expression))         \
    core_log_fatal(&self->_log, __FILE__, __LINE__, "out of memory")
#define lpfatal_oom(expression) \
    if (!(expression))          \
    core_log_fatal(self->_log, __FILE__, __LINE__, "out of memory")
#define mlfatal_oom(expression) \
    if (!(expression))          \
    core_log_fatal(&_log, __FILE__, __LINE__, "out of memory")
#define glfatal_oom(expression) \
    if (!(expression))          \
    core_log_fatal(0, __FILE__, __LINE__, "out of memory")

#endif

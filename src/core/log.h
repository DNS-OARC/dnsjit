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

#include "core/log.hh"

#define ldebug(msg...) log_debug(&self->_log, __FILE__, __LINE__, msg)
#define linfo(msg...) log_info(&self->_log, __FILE__, __LINE__, msg)
#define lnotice(msg...) log_notice(&self->_log, __FILE__, __LINE__, msg)
#define lwarning(msg...) log_warning(&self->_log, __FILE__, __LINE__, msg)
#define lcritical(msg...) log_critical(&self->_log, __FILE__, __LINE__, msg)
#define lfatal(msg...) log_fatal(&self->_log, __FILE__, __LINE__, msg)

#define lpdebug(msg...) log_debug(self->_log, __FILE__, __LINE__, msg)
#define lpinfo(msg...) log_info(self->_log, __FILE__, __LINE__, msg)
#define lpnotice(msg...) log_notice(self->_log, __FILE__, __LINE__, msg)
#define lpwarning(msg...) log_warning(self->_log, __FILE__, __LINE__, msg)
#define lpcritical(msg...) log_critical(self->_log, __FILE__, __LINE__, msg)
#define lpfatal(msg...) log_fatal(self->_log, __FILE__, __LINE__, msg)

#define mldebug(msg...) log_debug(&_log, __FILE__, __LINE__, msg)
#define mlinfo(msg...) log_info(&_log, __FILE__, __LINE__, msg)
#define mlnotice(msg...) log_notice(&_log, __FILE__, __LINE__, msg)
#define mlwarning(msg...) log_warning(&_log, __FILE__, __LINE__, msg)
#define mlcritical(msg...) log_critical(&_log, __FILE__, __LINE__, msg)
#define mlfatal(msg...) log_fatal(&_log, __FILE__, __LINE__, msg)

#define gldebug(msg...) log_debug(0, __FILE__, __LINE__, msg)
#define glinfo(msg...) log_info(0, __FILE__, __LINE__, msg)
#define glnotice(msg...) log_notice(0, __FILE__, __LINE__, msg)
#define glwarning(msg...) log_warning(0, __FILE__, __LINE__, msg)
#define glcritical(msg...) log_critical(0, __FILE__, __LINE__, msg)
#define glfatal(msg...) log_fatal(0, __FILE__, __LINE__, msg)

#endif

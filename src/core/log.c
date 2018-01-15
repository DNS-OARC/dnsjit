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

#include "core/log.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

static log_t _log = LOG_T_INIT;

log_t* core_log()
{
    return &_log;
}

struct _name {
    const char* debug;
    const char* info;
    const char* notice;
    const char* warning;
    const char* critical;
    const char* fatal;
};
static struct _name _name = {
    "debug",
    "info",
    "notice",
    "warning",
    "critical",
    "fatal"
};

#define log_func(name, level)                                                      \
    void name(const log_t* l, const char* file, size_t line, const char* msg, ...) \
    {                                                                              \
        char    buf[512];                                                          \
        va_list ap;                                                                \
        if (!l)                                                                    \
            l = &_log;                                                             \
        if (l->level == 3 || (_log.level == 3 && l->level != 2)) {                 \
            va_start(ap, msg);                                                     \
            vsnprintf(buf, sizeof(buf), msg, ap);                                  \
            va_end(ap);                                                            \
            buf[sizeof(buf) - 1] = 0;                                              \
            printf("%s[%lu] %s: %s\n", file, line, _name.level, buf);              \
        }                                                                          \
    }

log_func(log_debug, debug);
log_func(log_info, info);
log_func(log_notice, notice);
log_func(log_warning, warning);

void log_critical(const log_t* l, const char* file, size_t line, const char* msg, ...)
{
    char    buf[512];
    va_list ap;
    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    printf("%s[%lu] %s: %s\n", file, line, _name.critical, buf);
}

void log_fatal(const log_t* l, const char* file, size_t line, const char* msg, ...)
{
    char    buf[512];
    va_list ap;
    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    printf("%s[%lu] %s: %s\n", file, line, _name.fatal, buf);
    exit(1);
}

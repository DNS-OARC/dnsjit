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

typedef struct log_settings {
    unsigned short debug : 2;
    unsigned short info : 2;
    unsigned short notice : 2;
    unsigned short warning : 2;
    unsigned short display_file_line : 2;
} log_settings_t;

typedef struct log {
    const char*           name;
    unsigned short        is_obj : 1;
    log_settings_t        settings;
    const log_settings_t* module;
} log_t;

void log_debug(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_info(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_notice(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_warning(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_critical(const log_t* l, const char* file, size_t line, const char* msg, ...);
void log_fatal(const log_t* l, const char* file, size_t line, const char* msg, ...);

log_t* core_log();

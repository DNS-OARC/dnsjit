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

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")

typedef struct output_tcpcli {
    core_log_t _log;
    size_t     pkts, errs;
    int        fd;
} output_tcpcli_t;

core_log_t* output_tcpcli_log();

int output_tcpcli_init(output_tcpcli_t* self, const char* host, const char* port);
int output_tcpcli_destroy(output_tcpcli_t* self);

core_receiver_t output_tcpcli_receiver();

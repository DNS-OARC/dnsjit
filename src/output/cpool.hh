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

#if 0
typedef struct {} client_pool_t;
#endif
//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")
typedef struct output_cpool {
    log_t          _log;
    client_pool_t* p;
} output_cpool_t;

log_t* output_cpool_log();
int output_cpool_init(output_cpool_t* self, const char* host, const char* port);
int output_cpool_destroy(output_cpool_t* self);
size_t output_cpool_max_clients(output_cpool_t* self);
int output_cpool_set_max_clients(output_cpool_t* self, size_t max_clients);
double output_cpool_client_ttl(output_cpool_t* self);
int output_cpool_set_client_ttl(output_cpool_t* self, double client_ttl);
size_t output_cpool_max_reuse_clients(output_cpool_t* self);
int output_cpool_set_max_reuse_clients(output_cpool_t* self, size_t max_reuse_clients);
int output_cpool_skip_reply(output_cpool_t* self);
int output_cpool_set_skip_reply(output_cpool_t* self, int skip_reply);
const char* output_cpool_sendas(output_cpool_t* self);
int output_cpool_set_sendas_original(output_cpool_t* self);
int output_cpool_set_sendas_udp(output_cpool_t* self);
int output_cpool_set_sendas_tcp(output_cpool_t* self);
int output_cpool_dry_run(output_cpool_t* self);
int output_cpool_set_dry_run(output_cpool_t* self, int dry_run);
int output_cpool_start(output_cpool_t* self);
int output_cpool_stop(output_cpool_t* self);

receiver_t output_cpool_receiver();

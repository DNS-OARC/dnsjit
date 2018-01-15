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
//lua:require("dnsjit.core.log_h")
//lua:require("dnsjit.core.receiver_h")
typedef struct output_client_pool {
    log_t          log;
    client_pool_t* p;
} output_client_pool_t;

int output_client_pool_init(output_client_pool_t* self, const char* host, const char* port);
int output_client_pool_destroy(output_client_pool_t* self);
void output_client_pool_updatelog(output_client_pool_t* self);
size_t output_client_pool_max_clients(output_client_pool_t* self);
int output_client_pool_set_max_clients(output_client_pool_t* self, size_t max_clients);
double output_client_pool_client_ttl(output_client_pool_t* self);
int output_client_pool_set_client_ttl(output_client_pool_t* self, double client_ttl);
size_t output_client_pool_max_reuse_clients(output_client_pool_t* self);
int output_client_pool_set_max_reuse_clients(output_client_pool_t* self, size_t max_reuse_clients);
int output_client_pool_skip_reply(output_client_pool_t* self);
int output_client_pool_set_skip_reply(output_client_pool_t* self, int skip_reply);
const char* output_client_pool_sendas(output_client_pool_t* self);
int output_client_pool_set_sendas_original(output_client_pool_t* self);
int output_client_pool_set_sendas_udp(output_client_pool_t* self);
int output_client_pool_set_sendas_tcp(output_client_pool_t* self);
int output_client_pool_dry_run(output_client_pool_t* self);
int output_client_pool_set_dry_run(output_client_pool_t* self, int dry_run);
int output_client_pool_start(output_client_pool_t* self);
int output_client_pool_stop(output_client_pool_t* self);

receiver_t output_client_pool_receiver();

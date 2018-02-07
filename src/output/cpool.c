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

#include "output/cpool.h"

static log_t          _log      = LOG_T_INIT("output.cpool");
static output_cpool_t _defaults = {
    LOG_T_INIT_OBJ("output.cpool"),
    0
};

log_t* output_cpool_log()
{
    return &_log;
}

int output_cpool_init(output_cpool_t* self, const char* host, const char* port)
{
    if (!self || !host || !port) {
        return 1;
    }

    ldebug("init %p %s %s", self, host, port);

    *self = _defaults;

    if (!(self->p = client_pool_new(host, port))) {
        lfatal("oom");
    }
    self->p->_log = &self->_log;

    return 0;
}

int output_cpool_destroy(output_cpool_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy %p", self);

    client_pool_free(self->p);

    return 0;
}

size_t output_cpool_max_clients(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 0;
    }

    return self->p->max_clients;
}

int output_cpool_set_max_clients(output_cpool_t* self, size_t max_clients)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("max_clients %p %lu", self, max_clients);

    self->p->max_clients = max_clients;

    return 0;
}

double output_cpool_client_ttl(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 0;
    }

    return self->p->client_ttl;
}

int output_cpool_set_client_ttl(output_cpool_t* self, double client_ttl)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("client_ttl %p %f", self, client_ttl);

    self->p->client_ttl = client_ttl;

    return 0;
}

size_t output_cpool_max_reuse_clients(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 0;
    }

    return self->p->max_reuse_clients;
}

int output_cpool_set_max_reuse_clients(output_cpool_t* self, size_t max_reuse_clients)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("max_reuse_clients %p %lu", self, max_reuse_clients);

    self->p->max_reuse_clients = max_reuse_clients;

    return 0;
}

int output_cpool_skip_reply(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 0;
    }

    return self->p->client_skip_reply;
}

int output_cpool_set_skip_reply(output_cpool_t* self, int skip_reply)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("skip_reply %p %lu", self, skip_reply);

    self->p->client_skip_reply = skip_reply ? 1 : 0;

    return 0;
}

const char* output_cpool_sendas(output_cpool_t* self)
{
    if (!self || !self->p) {
        return "unknown";
    }

    switch (self->p->sendas) {
    case CLIENT_POOL_SENDAS_ORIGINAL:
        return "original";
    case CLIENT_POOL_SENDAS_UDP:
        return "udp";
    case CLIENT_POOL_SENDAS_TCP:
        return "tcp";
    default:
        break;
    }

    return "unknown";
}

int output_cpool_set_sendas_original(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("sendas original %p", self);

    self->p->sendas = CLIENT_POOL_SENDAS_ORIGINAL;

    return 0;
}

int output_cpool_set_sendas_udp(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("sendas udp %p", self);

    self->p->sendas = CLIENT_POOL_SENDAS_ORIGINAL;

    return 0;
}

int output_cpool_set_sendas_tcp(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("sendas tcp %p", self);

    self->p->sendas = CLIENT_POOL_SENDAS_ORIGINAL;

    return 0;
}

int output_cpool_dry_run(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 0;
    }

    return self->p->dry_run;
}

int output_cpool_set_dry_run(output_cpool_t* self, int dry_run)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("dry_run %p %lu", self, dry_run);

    self->p->dry_run = dry_run ? 1 : 0;

    return 0;
}

int output_cpool_start(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 1;
    }

    if (client_pool_start(self->p)) {
        return 1;
    }

    return 0;
}

int output_cpool_stop(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 1;
    }

    if (client_pool_stop(self->p)) {
        return 1;
    }

    return 0;
}

static int _receive(void* robj, query_t* q)
{
    output_cpool_t* self = (output_cpool_t*)robj;
    query_t*        copy;

    if (!self || !q || !self->p) {
        query_free(q);
        return 1;
    }

    if (!(copy = query_copy(q))) {
        query_free(q);
        return 1;
    }

    if (client_pool_query(self->p, copy)) {
        ldebug("client_pool_query failed");
        query_free(copy);
        query_free(q);
        return 1;
    }

    query_free(q);
    return 0;
}

receiver_t output_cpool_receiver()
{
    return _receive;
}

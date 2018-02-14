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

static core_log_t     _log      = LOG_T_INIT("output.cpool");
static output_cpool_t _defaults = {
    LOG_T_INIT_OBJ("output.cpool"),
    0
};

core_log_t* output_cpool_log()
{
    return &_log;
}

int output_cpool_init(output_cpool_t* self, const char* host, const char* port, size_t queue_size)
{
    if (!self || !host || !port) {
        return 1;
    }

    *self = _defaults;

    ldebug("init %s %s %lu", host, port, queue_size);

    if (!(self->p = client_pool_new(host, port, queue_size))) {
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

    ldebug("destroy");

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

    ldebug("max_clients %lu", max_clients);

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

    ldebug("client_ttl %f", client_ttl);

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

    ldebug("max_reuse_clients %lu", max_reuse_clients);

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

    ldebug("skip_reply %lu", skip_reply);

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

    ldebug("sendas original");

    self->p->sendas = CLIENT_POOL_SENDAS_ORIGINAL;

    return 0;
}

int output_cpool_set_sendas_udp(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("sendas udp");

    self->p->sendas = CLIENT_POOL_SENDAS_UDP;

    return 0;
}

int output_cpool_set_sendas_tcp(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 1;
    }

    ldebug("sendas tcp");

    self->p->sendas = CLIENT_POOL_SENDAS_TCP;

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

    ldebug("dry_run %lu", dry_run);

    self->p->dry_run = dry_run ? 1 : 0;

    return 0;
}

void _client_read(void* vp, const client_t* client)
{
    output_cpool_t* self = (output_cpool_t*)vp;
    core_query_t*   q;

    if (!self || !self->recv || !client) {
        return;
    }
    if (client->nrecv > 2) {
        if (!(q = core_query_new())) {
            return;
        }
        if (core_query_copy_addr(q, client->query)) {
            core_query_free(q);
            return;
        }
        if (client->is_stream) {
            q->is_tcp = 1;
            if (core_query_set_raw(q, client->recvbuf + 2, client->nrecv - 2)) {
                core_query_free(q);
                return;
            }
        } else {
            q->is_udp = 1;
            if (core_query_set_raw(q, client->recvbuf, client->nrecv)) {
                core_query_free(q);
                return;
            }
        }
        q->src_id = client->query->src_id;
        q->qr_id  = client->query->qr_id;
        q->dst_id = client->query->dst_id;

        self->recv(self->robj, q);
    } else if (!client->nrecv && client->query) {
        if (!(q = core_query_copy(client->query))) {
            return;
        }
        self->recv(self->robj, q);
    }
}

int output_cpool_start(output_cpool_t* self)
{
    if (!self || !self->p) {
        return 1;
    }

    if (self->recv) {
        self->p->client_always_read  = 1;
        self->p->client_recvbuf_size = 4 * 1024;
        self->p->client_read         = _client_read;
        self->p->client_read_ctx     = self;
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

static int _receive(void* robj, core_query_t* q)
{
    output_cpool_t* self = (output_cpool_t*)robj;
    core_query_t*   copy;

    if (!self || !q || !self->p) {
        core_query_free(q);
        return 1;
    }

    if (!(copy = core_query_copy(q))) {
        core_query_free(q);
        return 1;
    }

    if (client_pool_query(self->p, copy)) {
        ldebug("client_pool_query failed");
        core_query_free(copy);
        core_query_free(q);
        return 1;
    }

    core_query_free(q);
    return 0;
}

core_receiver_t output_cpool_receiver()
{
    return _receive;
}

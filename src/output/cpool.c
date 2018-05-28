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

#include <string.h>
#include <netinet/in.h>

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

static void _client_read(void* vp, const client_t* client)
{
    output_cpool_t* self = (output_cpool_t*)vp;

    if (!self || !self->recv || !client || !client->query) {
        return;
    }
    if (client->nrecv > 0) {
        core_object_packet_t pkt = CORE_OBJECT_PACKET_INIT(client->query);
        ev_tstamp            ts  = client->recvts - client->sendts;
        if (ts < 0.) {
            ts = 0.;
        }

        pkt.src_id = client->query->src_id;
        pkt.qr_id  = client->query->qr_id;
        pkt.dst_id = client->query->dst_id;

        if (client->is_stream) {
            pkt.is_tcp = 1;
        } else {
            pkt.is_udp = 1;
        }
        pkt.is_ipv6 = client->query->is_ipv6;

        pkt.src_addr = client->query->dst_addr;
        pkt.dst_addr = client->query->src_addr;

        pkt.sport   = client->query->dport;
        pkt.dport   = client->query->sport;
        pkt.ts.sec  = ts;
        pkt.ts.nsec = (long)(ts * 1000) % 1000;

        pkt.payload = (uint8_t*)client->recvbuf;
        pkt.len     = client->nrecv;

        self->recv(self->ctx, (core_object_t*)&pkt);
    } else {
        self->recv(self->ctx, (core_object_t*)client->query);
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

struct _packet {
    core_object_packet_t    pkt;
    struct sockaddr_storage src, dst;
    uint8_t                 payload[];
};

static int _receive(void* ctx, const core_object_t* obj)
{
    output_cpool_t*             self = (output_cpool_t*)ctx;
    const core_object_packet_t* pkt  = (core_object_packet_t*)obj;

    if (!self || !obj || !self->p) {
        return 1;
    }

    while (pkt) {
        if (pkt->obj_type == CORE_OBJECT_PACKET) {
            struct _packet* q;

            if (!(q = malloc(sizeof(struct _packet) + pkt->len))) {
                return 1;
            }
            *(core_object_packet_t*)q = *pkt;
            q->pkt.src_addr           = &q->src;
            q->pkt.dst_addr           = &q->dst;
            q->pkt.payload            = q->payload;
            memcpy(q->payload, pkt->payload, pkt->len);
            if (pkt->is_ipv6) {
                memcpy(&q->src, pkt->src_addr, sizeof(struct in6_addr));
                memcpy(&q->dst, pkt->dst_addr, sizeof(struct in6_addr));
            } else {
                memcpy(&q->src, pkt->src_addr, sizeof(struct in_addr));
                memcpy(&q->dst, pkt->dst_addr, sizeof(struct in_addr));
            }

            if (client_pool_query(self->p, (core_object_packet_t*)q)) {
                ldebug("client_pool_query failed");
                free(q);
                return 1;
            }
            return 0;
        }
        pkt = (core_object_packet_t*)pkt->obj_prev;
    }

    return 1;
}

core_receiver_t output_cpool_receiver()
{
    return _receive;
}

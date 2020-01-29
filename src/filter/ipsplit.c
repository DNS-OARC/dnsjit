/*
 * Copyright (c) 2019-2020, CZ.NIC, z.s.p.o.
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

#include "filter/ipsplit.h"

typedef struct _filter_ipsplit {
    filter_ipsplit_t pub;

    trie_t* trie;
} _filter_ipsplit_t;

typedef struct _client {
    uint8_t id[4];
    filter_ipsplit_recv_t* recv;
} _client_t;

#define _self ((_filter_ipsplit_t*)self)

static core_log_t     _log      = LOG_T_INIT("filter.ipsplit");
static filter_ipsplit_t _defaults = {
    LOG_T_INIT_OBJ("filter.ipsplit"),
    0,
    NULL
};

core_log_t* filter_ipsplit_log()
{
    return &_log;
}

filter_ipsplit_t* filter_ipsplit_new()
{
    filter_ipsplit_t* self;

    mlfatal_oom(self = malloc(sizeof(_filter_ipsplit_t)));
    *self = _defaults;
    _self->trie = trie_create(NULL);

    return self;
}

static int _free_trie_value(trie_val_t *val, void *ctx)
{
    (void*)ctx;
    free(*val);
    return 0;
}

void filter_ipsplit_free(filter_ipsplit_t* self)
{
    filter_ipsplit_recv_t* first;
    filter_ipsplit_recv_t* r;
    mlassert_self();

    trie_apply(_self->trie, _free_trie_value, NULL);
    trie_free(_self->trie);

    if (self->recv) {
        first = self->recv;
        do {
            r = self->recv->next;
            free(self->recv);
            self->recv = r;
        } while (self->recv != first);
    }

    free(self);
}

void filter_ipsplit_add(filter_ipsplit_t* self, core_receiver_t recv, void* ctx)
{
    filter_ipsplit_recv_t* r;
    mlassert_self();
    lassert(recv, "recv is nil");

    lfatal_oom(r = malloc(sizeof(filter_ipsplit_recv_t)));
    r->recv = recv;
    r->ctx = ctx;
    r->client = 1;

    if (!self->recv) {
        r->next = r;
        self->recv = r;
    } else {
        r->next = self->recv->next;
        self->recv->next = r;
    }
}

static void _receive(filter_ipsplit_t* self, const core_object_t* obj)
{
    core_object_t* pkt;
    core_object_ip6_t* ip6;
    _client_t* client;
    trie_val_t* val;
    uint32_t id;
    mlassert_self();

    if (!obj) {
        self->discarded++;
        linfo("packet discarded (no data)");
    }

    pkt = (core_object_t*)obj;
    do {
        if (pkt->obj_type == CORE_OBJECT_IP6) {
            ip6 = (core_object_ip6_t*)pkt;
            val = trie_get_ins(_self->trie, ip6->src, sizeof(ip6->src));
            if (*val == NULL) {  // new client
                lfatal_oom(client = malloc(sizeof(_client_t)));
                *val = (void*)client;
                client->recv = self->recv;
                self->recv = self->recv->next;
                id = client->recv->client++;
                memcpy(client->id, &id, sizeof(client->id));
            } else {
                client = (_client_t*)*val;
            }
            // put the client ID into dst IP
            memcpy(&ip6->dst, client->id, sizeof(client->id));
            client->recv->recv(client->recv->ctx, obj);
            return;
        }
        pkt = (core_object_t*)pkt->obj_prev;
    } while (pkt != NULL);

    lwarning("packet discarded (missing ip6 object)");
}

core_receiver_t filter_ipsplit_receiver(filter_ipsplit_t* self)
{
    if (!self->recv) {
        lfatal("no receiver(s) set");
    }

    return (core_receiver_t)_receive;
}

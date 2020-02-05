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
    uint32_t weight_total;
} _filter_ipsplit_t;

typedef struct _client {
    /* Receiver-specific client ID (1..N) in host byte order. */
    /* Client ID starts at 1 to avoid issues with lua. */
    uint8_t id[4];

    filter_ipsplit_recv_t* recv;
} _client_t;

#define _self ((_filter_ipsplit_t*)self)

static core_log_t     _log      = LOG_T_INIT("filter.ipsplit");
static filter_ipsplit_t _defaults = {
    LOG_T_INIT_OBJ("filter.ipsplit"),
    IPSPLIT_MODE_SEQUENTIAL, IPSPLIT_OVERWRITE_NONE,
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
    _self->weight_total = 0;

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

void filter_ipsplit_add(filter_ipsplit_t* self, core_receiver_t recv, void* ctx, uint32_t weight)
{
    filter_ipsplit_recv_t* r;
    mlassert_self();
    lassert(recv, "recv is nil");
    lassert(weight > 0, "weight must be positive integer");

    _self->weight_total += weight;

    lfatal_oom(r = malloc(sizeof(filter_ipsplit_recv_t)));
    r->recv = recv;
    r->ctx = ctx;
    r->n_clients = 0;
    r->weight = weight;

    if (!self->recv) {
        r->next = r;
        self->recv = r;
    } else {
        r->next = self->recv->next;
        self->recv->next = r;
    }
}

/*
 * Use portable pseudo-random number generator.
 */
static unsigned long _rand_next = 1;

static unsigned int _rand(unsigned int mod) {
   mlassert(mod >= 1, "modulus must be positive integer");
   _rand_next = _rand_next * 1103515245 + 12345;
   unsigned int ret = (unsigned)(_rand_next/65536) % mod;
   mldebug("rand: %d", ret);
   return ret;
}

void filter_ipsplit_srand(unsigned int seed) {
   _rand_next = seed;
   mldebug("rand seed %d", seed);
}

static void _assign_client_to_receiver(filter_ipsplit_t* self, _client_t* client)
{
    uint32_t id;
    filter_ipsplit_recv_t* recv;

    switch (self->mode) {
    case IPSPLIT_MODE_SEQUENTIAL:
        recv = self->recv;
        id = ++recv->n_clients;
        /* When *weight* clients are assigned, switch to next receiver. */
        if (recv->n_clients % recv->weight == 0)
            self->recv = recv->next;
        break;
    case IPSPLIT_MODE_RANDOM: {
        /* Get random number from [1, weight_total], then iterate through
         * receivers until their weights add up to at least this value. */
        int32_t random = (int32_t)_rand(_self->weight_total) + 1;
        while (random > 0) {
            random -= self->recv->weight;
            if (random > 0)
                self->recv = self->recv->next;
        }
        recv = self->recv;
        id = ++recv->n_clients;
        break;
    }
    default:
        lfatal("invalid ipsplit mode");
    }

    client->recv = recv;
    memcpy(client->id, &id, sizeof(client->id));
}

/*
 * Optionally, write client ID into byte 0-3 of src/dst IP address in the packet.
 *
 * Client ID is a 4-byte array in host byte order.
 */
static void _overwrite(filter_ipsplit_t* self, core_object_t* obj, _client_t* client)
{
    mlassert_self();
    mlassert(obj, "invalid object");
    mlassert(client, "invalid client");

    core_object_ip_t* ip;
    core_object_ip6_t* ip6;

    switch(self->overwrite) {
    case IPSPLIT_OVERWRITE_NONE:
        return;
    case IPSPLIT_OVERWRITE_SRC:
        if (obj->obj_type == CORE_OBJECT_IP) {
            ip = (core_object_ip_t*)obj;
            memcpy(&ip->src, client->id, sizeof(client->id));
        } else if (obj->obj_type == CORE_OBJECT_IP6) {
            ip6 = (core_object_ip6_t*)obj;
            memcpy(&ip6->src, client->id, sizeof(client->id));
        }
        break;
    case IPSPLIT_OVERWRITE_DST:
        if (obj->obj_type == CORE_OBJECT_IP) {
            ip = (core_object_ip_t*)obj;
            memcpy(&ip->dst, client->id, sizeof(client->id));
        } else if (obj->obj_type == CORE_OBJECT_IP6) {
            ip6 = (core_object_ip6_t*)obj;
            memcpy(&ip6->dst, client->id, sizeof(client->id));
        }
        break;
    default:
        lfatal("invalid overwrite mode");
    }
}

static void _receive(filter_ipsplit_t* self, const core_object_t* obj)
{
    mlassert_self();

    /* Find ip/ip6 object in chain. */
    core_object_t* pkt = (core_object_t*)obj;
    while (pkt != NULL) {
        if (pkt->obj_type == CORE_OBJECT_IP || pkt->obj_type == CORE_OBJECT_IP6)
            break;
        pkt = (core_object_t*)pkt->obj_prev;
    }
    if (pkt == NULL) {
        self->discarded++;
        lwarning("packet discarded (missing ip/ip6 object)");
        return;
    }

    /* Lookup IPv4/IPv6 address in trie (prefix-tree). Inserts new node if not found. */
    trie_val_t* node;
    switch(pkt->obj_type) {
    case CORE_OBJECT_IP: {
        core_object_ip_t* ip = (core_object_ip_t*)pkt;
        node = trie_get_ins(_self->trie, ip->src, sizeof(ip->src));
        break;
    }
    case CORE_OBJECT_IP6: {
        core_object_ip6_t* ip6 = (core_object_ip6_t*)pkt;
        node = trie_get_ins(_self->trie, ip6->src, sizeof(ip6->src));
        break;
    }
    default:
        lfatal("unsupported object type");
    }
    lassert(node, "trie failure");

    _client_t* client;
    if (*node == NULL) {  /* IP address not found in tree -> create new client. */
        lfatal_oom(client = malloc(sizeof(_client_t)));
        *node = (void*)client;
        _assign_client_to_receiver(self, client);
    }

    client = (_client_t*)*node;
    _overwrite(self, pkt, client);
    client->recv->recv(client->recv->ctx, obj);
}

core_receiver_t filter_ipsplit_receiver(filter_ipsplit_t* self)
{
    if (!self->recv) {
        lfatal("no receiver(s) set");
    }

    return (core_receiver_t)_receive;
}

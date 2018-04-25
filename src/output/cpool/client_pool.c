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

#include "output/cpool/client_pool.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <netinet/in.h>

#define ev_async_init_(ev, cb) \
    {                          \
        ev_async* p = &ev;     \
        ev_async_init(p, cb);  \
    }
#define ev_timer_init_(ev, cb, a, b) \
    {                                \
        ev_timer* p = &ev;           \
        ev_timer_init(p, cb, a, b);  \
    }
#define ev_timer_set_(ev, a, b) \
    {                           \
        ev_timer* p = &ev;      \
        ev_timer_set(p, a, b);  \
    }
#define ev_is_active_(ev) (ev_is_active__((ev_watcher*)ev))
static inline int ev_is_active__(ev_watcher* p)
{
    return ev_is_active(p);
}

/*
 * List helpers
 */
static inline void client_list_add(client_pool_t* self, client_t* client, struct ev_loop* loop)
{
    if (self->client_list_last) {
        client_set_next(self->client_list_last, client);
        client_set_prev(client, self->client_list_last);
    }
    self->client_list_last = client;
    if (!self->client_list_first)
        self->client_list_first = client;
    self->clients++;

    if (!ev_is_active_(&self->timeout)) {
        ev_tstamp timeout = ev_now(loop) - client_start(self->client_list_first);

        if (timeout < 0.)
            timeout = 0.;
        else if (timeout > self->client_ttl)
            timeout = self->client_ttl;

        ev_timer_set_(self->timeout, timeout, 0.);
        ev_timer_start(loop, &(self->timeout));
    }
}

static inline void client_list_remove(client_pool_t* self, client_t* client, struct ev_loop* loop)
{
    if (client == self->client_list_first) {
        self->client_list_first = client_next(client);
    }
    if (client == self->client_list_last) {
        self->client_list_last = client_prev(client);
    }
    if (client_next(client)) {
        client_set_prev(client_next(client), client_prev(client));
    }
    if (client_prev(client)) {
        client_set_next(client_prev(client), client_next(client));
    }
    client_set_next(client, 0);
    client_set_prev(client, 0);

    if (self->clients) {
        self->clients--;
    } else {
        lpdebug("removed client but clients already zero");
    }

    if (self->clients && ev_is_active_(&self->timeout)) {
        ev_timer_stop(loop, &(self->timeout));
    }
}

static inline void client_close_free(client_pool_t* self, client_t* client, struct ev_loop* loop)
{
    if (client_state(client) == CLIENT_CLOSED) {
        client_free(client);
        return;
    }

    if (client_close(client, loop)) {
        lpdebug("client close failed");
        client_free(client);
        return;
    }

    if (client_state(client) == CLIENT_CLOSING) {
        client_list_add(self, client, loop);
    } else {
        client_free(client);
    }
}

static inline void client_reuse_add(client_pool_t* self, client_t* client)
{
    client_set_next(client, self->reuse_client_list);
    client_set_prev(client, 0);
    self->reuse_client_list = client;
    self->reuse_clients++;
}

static inline client_t* client_reuse_get(client_pool_t* self)
{
    client_t* client = self->reuse_client_list;

    if (client) {
        self->reuse_client_list = client_next(client);
        if (self->reuse_clients) {
            self->reuse_clients--;
        } else {
            lpdebug("remove reuse client but reuse_clients already zero");
        }
        client_set_next(client, 0);
        client_set_prev(client, 0);
    }

    return client;
}

/*
 * New/free
 */

static sllq_t client_pool_sllq_init = SLLQ_T_INIT;

client_pool_t* client_pool_new(const char* host, const char* port, size_t queue_size)
{
    client_pool_t* self;

    if (!host || !port) {
        return 0;
    }
    if (!queue_size) {
        queue_size = 0x200;
    }

    if ((self = calloc(1, sizeof(client_pool_t)))) {
        struct addrinfo hints;
        int             err;

        self->max_clients       = 100;
        self->client_ttl        = 0.05;
        self->max_reuse_clients = 20;
        self->sendas            = CLIENT_POOL_SENDAS_ORIGINAL;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        if ((err = getaddrinfo(host, port, &hints, &(self->addrinfo)))) {
            lpdebug("getaddrinfo: %s", gai_strerror(err));
            free(self);
            return 0;
        }
        if (!self->addrinfo) {
            lpdebug("getaddrinfo failed");
            free(self);
            return 0;
        }
        lpdebug("getaddrinfo() flags: 0x%x family: 0x%x socktype: 0x%x protocol: 0x%x addrlen: %d",
            self->addrinfo->ai_flags,
            self->addrinfo->ai_family,
            self->addrinfo->ai_socktype,
            self->addrinfo->ai_protocol,
            self->addrinfo->ai_addrlen);

        memcpy(&(self->queries), &client_pool_sllq_init, sizeof(sllq_t));
        sllq_set_size(&(self->queries), queue_size);
        if (sllq_init(&(self->queries)) != SLLQ_OK) {
            freeaddrinfo(self->addrinfo);
            free(self);
            return 0;
        }

        if (!(self->ev_loop = ev_loop_new(EVFLAG_NOSIGMASK))) {
            freeaddrinfo(self->addrinfo);
            sllq_destroy(&(self->queries));
            free(self);
            return 0;
        }

        ev_set_userdata(self->ev_loop, (void*)self);
    }

    return self;
}

static void client_pool_free_query(void* vp)
{
    free(vp);
}

void client_pool_free(client_pool_t* self)
{
    if (self) {
        sllq_flush(&(self->queries), &client_pool_free_query);
        sllq_destroy(&(self->queries));
        if (self->ev_loop)
            ev_loop_destroy(self->ev_loop);
        if (self->addrinfo)
            freeaddrinfo(self->addrinfo);
        while (self->reuse_client_list) {
            client_t* client        = self->reuse_client_list;
            self->reuse_client_list = client_next(client);
            client_free(client);
        }
        free(self);
    }
}

/*
 * Engine
 */

static void* client_pool_engine(void* vp)
{
    client_pool_t* self = (client_pool_t*)vp;

    assert(self);
    if (self) {
        assert(self->ev_loop);
        lpdebug("client pool ev run");
        ev_run(self->ev_loop, 0);
        lpdebug("client pool ev run exited");
    }

    return 0;
}

static void client_pool_client_callback(client_t* client, struct ev_loop* loop)
{
    client_pool_t* self = (client_pool_t*)ev_userdata(loop);

    assert(client);
    if (!client) {
        return;
    }
    assert(self);
    if (!self) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }

    if (client_state(client) == CLIENT_CONNECTED) {
        lpdebug("client connected");
        if (client_send(client, loop)) {
            lpdebug("client failed to send");
        } else if (client_state(client) == CLIENT_RECIVING) {
            return;
        }
    }

    client_list_remove(self, client, loop);

    switch (client_state(client)) {
    case CLIENT_SUCCESS:
        lpdebug("client success");
        if (self->client_read) {
            self->client_read(self->client_read_ctx, client);
        }
        if (client_is_dgram(client)
            && self->reuse_clients < self->max_reuse_clients) {
            client_reuse_add(self, client);
            lpdebug("client added to reuse (%lu/%lu)", self->reuse_clients, self->max_reuse_clients);
        } else {
            client_close_free(self, client, loop);
        }
        break;

    case CLIENT_FAILED:
        /* TODO */
        lpdebug("client failed");
        client_close_free(self, client, loop);
        break;

    case CLIENT_ERRNO:
        lpdebug("client errno");
        client_close_free(self, client, loop);
        break;

    case CLIENT_CLOSED:
        lpdebug("client closed");
        client_free(client);
        break;

    default:
        lpdebug("client state %d", client_state(client));
        client_close_free(self, client, loop);
        break;
    }

    ev_async_send(loop, &(self->notify_query));
}

static void client_pool_engine_timeout(struct ev_loop* loop, ev_timer* w, int revents)
{
    client_pool_t* self = (client_pool_t*)ev_userdata(loop);
    ev_tstamp      timeout;
    client_t *     client, *first_client = 0;

    /* TODO: Check revents for EV_ERROR */

    assert(self);
    if (!self) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }

    timeout = ev_now(loop) - self->client_ttl;

    while ((client = self->client_list_first) && client_start(self->client_list_first) <= timeout) {
        if (!first_client) {
            first_client = client;
        } else if (client == first_client) {
            break;
        }

        client_list_remove(self, client, loop);
        if (client_state(client) == CLIENT_CLOSING) {
            client_list_add(self, client, loop);
            continue;
        }

        lpdebug("client timeout");
        client_close_free(self, client, loop);
    }

    ev_async_send(loop, &(self->notify_query));
}

static void client_pool_engine_retry(struct ev_loop* loop, ev_timer* w, int revents)
{
    client_pool_t* self = (client_pool_t*)ev_userdata(loop);

    /* TODO: Check revents for EV_ERROR */

    assert(self);
    if (!self) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }

    if (self->query)
        ev_async_send(loop, &(self->notify_query));
    else
        ev_timer_stop(loop, w);
}

static void client_pool_engine_query(struct ev_loop* loop, ev_async* w, int revents)
{
    client_pool_t*        self = (client_pool_t*)ev_userdata(loop);
    core_object_packet_t* query;
    int                   err;

    /* TODO: Check revents for EV_ERROR */

    assert(self);
    if (!self) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }

    if (self->clients >= self->max_clients) {
        return;
    }

    /* TODO:
     *   store one query within the pool, keep retrying to create a client
     *   if fail, start a timer for retry and retry on each query call but
     *   do not add async
     */
    if (self->query) {
        query       = self->query;
        self->query = 0;
    } else {
        err = sllq_shift(&(self->queries), (void**)&query, 0);

        if (err == SLLQ_EMPTY) {
            if (self->is_stopping && self->reuse_clients) {
                client_t* client;
                while ((client = client_reuse_get(self))) {
                    client_close_free(self, client, loop);
                }
            }
            if (self->is_stopping && !self->clients) {
                ev_async_stop(loop, &(self->notify_query));
                ev_timer_stop(loop, &(self->timeout));
                ev_timer_stop(loop, &(self->retry));
            }
            return;
        } else if (err == SLLQ_EAGAIN) {
            ev_async_send(loop, &(self->notify_query));
            return;
        } else if (err) {
            if (err == SLLQ_ERRNO) {
                lpdebug("shift queue error %d: ", err);
            } else {
                lpdebug("shift queue error %d", err);
            }
            return;
        }
    }

    if (!query) {
        lpdebug("shift queue null?");
        ev_async_send(loop, &(self->notify_query));
        return;
    }

    if (self->dry_run) {
        lpdebug("shift queue, query %p (dry-run)", query);
        ev_async_send(loop, &(self->notify_query));
        return;
    } else {
        lpdebug("shift queue, query %p", query);
    }

    {
        client_t* client = 0;
        int       proto  = -1;

        switch (self->sendas) {
        case CLIENT_POOL_SENDAS_UDP:
            proto = IPPROTO_UDP;
            break;

        case CLIENT_POOL_SENDAS_TCP:
            proto = IPPROTO_TCP;
            break;

        default:
            if (query->is_udp) {
                proto = IPPROTO_UDP;
            } else if (query->is_tcp) {
                proto = IPPROTO_TCP;
            } else {
                lpdebug("unable to understand query protocol, surly a bug so please report this");
                free(query);
                ev_async_send(loop, &(self->notify_query));
                return;
            }
            break;
        }

        if (proto == IPPROTO_UDP
            && self->reuse_client_list) {
            client = client_reuse_get(self);
            if (client_reuse(client, query)) {
                lpdebug("reuse client failed");
                client_close_free(self, client, loop);
                client = 0;
            } else {
                /* client have taken ownership of query */
                query = 0;
            }

            if (client && client_set_start(client, ev_now(loop))) {
                lpdebug("reuse client start failed");
                query = client_release_query(client);
                client_close_free(self, client, loop);
                client = 0;
            }
        }

        if (!client && (client = client_new(query, &client_pool_client_callback))) {
            /* client have taken ownership of query */
            query = 0;

            client->always_read = self->client_always_read;

            /* TODO: Multiple addrinfo entries? */

            if (client_set_start(client, ev_now(loop))
                || (self->client_skip_reply && client_set_skip_reply(client))
                || (self->client_recvbuf_size && client_set_recvbuf_size(client, self->client_recvbuf_size))
                || client_connect(client, proto, self->addrinfo->ai_addr, self->addrinfo->ai_addrlen, loop)) {
                if (client_state(client) == CLIENT_ERRNO) {
                    lpdebug("client start/connect failed");
                } else {
                    lpdebug("client start/connect failed");
                }
                query = client_release_query(client);
                client_close_free(self, client, loop);
                client = 0;
            }
        }

        if (client) {
            if (self->client_read) {
                self->client_read(self->client_read_ctx, client);
            }
            if (client_state(client) == CLIENT_CONNECTED && client_send(client, loop)) {
                lpdebug("client send failed");
                client_close_free(self, client, loop);
            } else {
                if (client_state(client) == CLIENT_SUCCESS) {
                    lpdebug("client success");
                    if (self->client_read) {
                        self->client_read(self->client_read_ctx, client);
                    }
                    if (client_is_dgram(client)
                        && self->reuse_clients < self->max_reuse_clients) {
                        client_reuse_add(self, client);
                        lpdebug("client added to reuse (%lu/%lu)", self->reuse_clients, self->max_reuse_clients);
                    } else {
                        client_close_free(self, client, loop);
                    }
                } else {
                    client_list_add(self, client, loop);
                    lpdebug("new client (%lu/%lu)", self->clients, self->max_clients);
                }
            }
        } else if (query) {
            lpdebug("unable to create client, query requeued");
            self->query = query;
            if (!ev_is_active_(&self->retry)) {
                ev_timer_start(loop, &(self->retry));
            }
            return;
        } else {
            lpdebug("unable to create client, query lost");
        }
    }

    /* TODO: Can we optimize this? Not call it every time? */
    ev_async_send(loop, &(self->notify_query));
}

static void client_pool_engine_stop(struct ev_loop* loop, ev_async* w, int revents)
{
    client_pool_t* self = (client_pool_t*)ev_userdata(loop);
    client_t*      client;

    /* TODO: Check revents for EV_ERROR */

    assert(self);
    if (!self) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }

    self->is_stopping = 1;

    while ((client = client_reuse_get(self))) {
        client_close_free(self, client, loop);
    }
    ev_async_stop(loop, &(self->notify_stop));
    ev_async_send(loop, &(self->notify_query));
}

/*
 * Start/stop
 */

int client_pool_start(client_pool_t* self)
{
    int err;

    assert(self);
    if (!self) {
        return 1;
    }
    if (self->state != CLIENT_POOL_INACTIVE) {
        return 1;
    }
    assert(self->ev_loop);

    lpdebug("client pool ev init");

    ev_async_init_(self->notify_query, client_pool_engine_query);
    ev_async_init_(self->notify_stop, client_pool_engine_stop);
    ev_timer_init_(self->timeout, client_pool_engine_timeout, 0., 0.);
    ev_timer_init_(self->retry, client_pool_engine_retry, 1., 1.);

    ev_async_start(self->ev_loop, &(self->notify_query));
    ev_async_start(self->ev_loop, &(self->notify_stop));

    lpdebug("client pool starting");

    if ((err = pthread_create(&(self->thread_id), 0, &client_pool_engine, (void*)self))) {
        self->state = CLIENT_POOL_ERROR;
        errno       = err;
        return 1;
    }
    self->state = CLIENT_POOL_RUNNING;

    return 0;
}

int client_pool_stop(client_pool_t* self)
{
    int err;

    assert(self);
    if (!self) {
        return 1;
    }
    if (self->state != CLIENT_POOL_RUNNING) {
        return 1;
    }
    assert(self->ev_loop);

    lpdebug("client pool stopping");

    ev_async_send(self->ev_loop, &(self->notify_stop));

    if ((err = pthread_join(self->thread_id, 0))) {
        self->state = CLIENT_POOL_ERROR;
        errno       = err;
        return 1;
    }

    self->state = CLIENT_POOL_STOPPED;

    lpdebug("client pool stopped");

    return 0;
}

/*
 * Query/process
 */

int client_pool_query(client_pool_t* self, const core_object_packet_t* pkt)
{
    int err;

    assert(self);
    if (!self) {
        return 1;
    }
    if (!pkt || !pkt->payload || !pkt->len) {
        return 1;
    }
    if (self->state != CLIENT_POOL_RUNNING) {
        return 1;
    }
    assert(self->ev_loop);

    err = SLLQ_EAGAIN;
    while (err == SLLQ_EAGAIN || err == SLLQ_ETIMEDOUT || err == SLLQ_FULL) {
        struct timespec timeout;

        if (clock_gettime(CLOCK_REALTIME, &timeout)) {
            lpdebug("client pool query failed: clock_gettime()");
            return 1;
        }
        timeout.tv_nsec += 200000000;
        if (timeout.tv_nsec > 999999999) {
            timeout.tv_sec += timeout.tv_nsec / 1000000000;
            timeout.tv_nsec %= 1000000000;
        }

        err = sllq_push(&(self->queries), (void*)pkt, &timeout);
    }

    if (err) {
        if (err == SLLQ_ERRNO) {
            lpdebug("client pool query failed %d: ", err);
        } else {
            lpdebug("client pool query failed %d", err);
        }
        return 1;
    }

    lpdebug("client pool query ok, signaling");

    ev_async_send(self->ev_loop, &(self->notify_query));

    return 0;
}

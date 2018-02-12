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

#include "output/cpool/client.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>

/*
 * EV callbacks
 */

static void client_shutdown(struct ev_loop* loop, ev_io* w, int revents)
{
    client_t* client;
    char      buf[4 * 1024];

    /* TODO: Check revents for EV_ERROR */

    assert(loop);
    assert(w);
    client = (client_t*)(w->data);
    assert(client);

    if (recv(client->fd, buf, sizeof(buf), 0) > 0)
        return;

    ev_io_stop(loop, w);
    client->state = CLIENT_CLOSED;
    client->callback(client, loop);
}

static void client_read(struct ev_loop* loop, ev_io* w, int revents)
{
    client_t* client;
    ssize_t   nrecv;
    char      buf[4 * 1024];

    /* TODO: Check revents for EV_ERROR */

    assert(loop);
    assert(w);
    client = (client_t*)(w->data);
    assert(client);

    /* TODO: How much should we read? */

    /* TODO:
    if (client->have_from_addr)
        memset(&(client->from_addr), 0, sizeof(struct sockaddr_storage));
    client->from_addrlen = sizeof(struct sockaddr_storage);
    nrecv = recvfrom(client->fd, buf, sizeof(buf), 0, &(client->from_addr), &(client->from_addrlen));
    */
    nrecv = recvfrom(client->fd, buf, sizeof(buf), 0, 0, 0);
    if (nrecv < 0) {
        switch (errno) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            return;

        case ECONNREFUSED:
        case ENETUNREACH:
            client->state = CLIENT_FAILED;
            break;

        default:
            client->errnum = errno;
            client->state  = CLIENT_ERRNO;
            break;
        }
        ev_io_stop(loop, w);
        client->callback(client, loop);
        return;
    }
    /* TODO:
    else if (nrecv > 0) {
    }
*/

    ev_io_stop(loop, w);
    client->state = CLIENT_SUCCESS;
    client->callback(client, loop);
}

static void client_write(struct ev_loop* loop, ev_io* w, int revents)
{
    client_t* client;
    ssize_t   nsent;

    /* TODO: Check revents for EV_ERROR */

    assert(loop);
    assert(w);
    client = (client_t*)(w->data);
    assert(client);

    if (client->state == CLIENT_CONNECTING) {
        int       err = 0;
        socklen_t len = sizeof(err);

        ev_io_stop(loop, w);

        if (getsockopt(client->fd, SOL_SOCKET, SO_ERROR, (void*)&err, &len) < 0) {
            client->errnum = errno;
            client->state  = CLIENT_ERRNO;
        } else if (err) {
            switch (err) {
            case ECONNREFUSED:
            case ENETUNREACH:
                client->state = CLIENT_FAILED;
                break;

            default:
                client->errnum = err;
                client->state  = CLIENT_ERRNO;
                break;
            }
        } else {
            client->state        = CLIENT_CONNECTED;
            client->is_connected = 1;
        }

        client->callback(client, loop);
        return;
    }

    if (client->is_stream && !client->sent_length) {
        uint16_t length = htons(client->query->len);

        if (client->have_to_addr)
            nsent = sendto(client->fd, &length, 2, 0, (struct sockaddr*)&(client->to_addr), client->to_addrlen);
        else
            nsent = sendto(client->fd, &length, 2, 0, 0, 0);
        if (nsent < 0) {
            switch (errno) {
            case EAGAIN:
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
                return;

            default:
                break;
            }

            ev_io_stop(loop, w);
            client->errnum = errno;
            client->state  = errno == ECONNRESET ? CLIENT_FAILED : CLIENT_ERRNO;
            client->callback(client, loop);
            return;
        } else if (nsent != 2) {
            ev_io_stop(loop, w);
            client->errnum = ENOBUFS;
            client->state  = CLIENT_FAILED;
            client->callback(client, loop);
            return;
        }

        client->sent_length = 1;
    }

    if (client->have_to_addr)
        nsent = sendto(client->fd, core_query_raw(client->query) + client->sent, client->query->len - client->sent, 0, (struct sockaddr*)&(client->to_addr), client->to_addrlen);
    else
        nsent = sendto(client->fd, core_query_raw(client->query) + client->sent, client->query->len - client->sent, 0, 0, 0);
    if (nsent < 0) {
        switch (errno) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            return;

        default:
            break;
        }

        ev_io_stop(loop, w);
        client->errnum = errno;
        client->state  = errno == ECONNRESET ? CLIENT_FAILED : CLIENT_ERRNO;
        client->callback(client, loop);
        return;
    }

    client->sent += nsent;
    if (client->sent < client->query->len)
        return;

    ev_io_stop(loop, w);
    if (client->skip_reply) {
        client->state = CLIENT_SUCCESS;
        client->callback(client, loop);
        return;
    }
    ev_io_start(loop, &(client->read_watcher));
    client->state = CLIENT_RECIVING;
}

/*
 * New/free functions
 */

client_t* client_new(core_query_t* query, client_callback_t callback)
{
    client_t* client;

    assert(query);
    if (!query) {
        return 0;
    }
    assert(callback);
    if (!callback) {
        return 0;
    }

    if (!query->have_raw) {
        return 0;
    }

    if ((client = calloc(1, sizeof(client_t)))) {
        client->query              = query;
        client->callback           = callback;
        client->write_watcher.data = (void*)client;
        ev_init(&(client->write_watcher), &client_write);
        client->read_watcher.data = (void*)client;
        ev_init(&(client->read_watcher), &client_read);
        client->shutdown_watcher.data = (void*)client;
        ev_init(&(client->shutdown_watcher), &client_shutdown);
    }

    return client;
}

void client_free(client_t* client)
{
    if (client) {
        if (client->have_fd) {
            if (client->is_connected) {
                shutdown(client->fd, SHUT_RDWR);
            }
            close(client->fd);
        }
        if (client->query) {
            core_query_free(client->query);
        }
        free(client);
    }
}

/*
 * Get/set functions
 */

inline client_t* client_next(client_t* client)
{
    assert(client);
    return client->next;
}

inline client_t* client_prev(client_t* client)
{
    assert(client);
    return client->prev;
}

inline int client_fd(const client_t* client)
{
    assert(client);
    return client->fd;
}

inline const core_query_t* client_query(const client_t* client)
{
    assert(client);
    return client->query;
}

inline client_state_t client_state(const client_t* client)
{
    assert(client);
    return client->state;
}

inline int client_is_connected(const client_t* client)
{
    assert(client);
    return client->is_connected;
}

inline int client_errno(const client_t* client)
{
    assert(client);
    return client->errnum;
}

inline ev_tstamp client_start(const client_t* client)
{
    assert(client);
    return client->start;
}

inline int client_is_dgram(const client_t* client)
{
    assert(client);
    return client->is_dgram;
}

inline int client_is_stream(const client_t* client)
{
    assert(client);
    return client->is_stream;
}

int client_set_next(client_t* client, client_t* next)
{
    assert(client);
    if (!client) {
        return 1;
    }

    client->next = next;

    return 0;
}

int client_set_prev(client_t* client, client_t* prev)
{
    assert(client);
    if (!client) {
        return 1;
    }

    client->prev = prev;

    return 0;
}

int client_set_start(client_t* client, ev_tstamp start)
{
    assert(client);
    if (!client) {
        return 1;
    }

    client->start = start;

    return 0;
}

int client_set_skip_reply(client_t* client)
{
    assert(client);
    if (!client) {
        return 1;
    }

    client->skip_reply = 1;

    return 0;
}

core_query_t* client_release_query(client_t* client)
{
    core_query_t* query;

    assert(client);
    if (!client) {
        return 0;
    }

    query         = client->query;
    client->query = 0;

    return query;
}

/*
 * Control functions
 */

int client_connect(client_t* client, int ipproto, const struct sockaddr* addr, socklen_t addrlen, struct ev_loop* loop)
{
    int socket_type, flags;

    assert(client);
    if (!client) {
        return 1;
    }
    assert(addr);
    if (!addr) {
        return 1;
    }
    assert(addrlen);
    if (!addrlen) {
        return 1;
    }
    if (addrlen > sizeof(struct sockaddr_storage)) {
        return 1;
    }
    assert(loop);
    if (!loop) {
        return 1;
    }
    if (client->state != CLIENT_NEW) {
        return 1;
    }

    switch (ipproto) {
    case IPPROTO_UDP:
        socket_type = SOCK_DGRAM;
        memcpy(&(client->to_addr), addr, addrlen);
        client->to_addrlen   = addrlen;
        client->have_to_addr = 1;
        client->is_dgram     = 1;
        break;

    case IPPROTO_TCP:
        socket_type       = SOCK_STREAM;
        client->is_stream = 1;
        break;

    default:
        return 1;
    }

    if ((client->fd = socket(addr->sa_family, socket_type, ipproto)) < 0) {
        client->errnum = errno;
        client->state  = CLIENT_ERRNO;
        return 1;
    }
    client->have_fd = 1;

    if ((flags = fcntl(client->fd, F_GETFL)) == -1
        || fcntl(client->fd, F_SETFL, flags | O_NONBLOCK)) {
        client->errnum = errno;
        client->state  = CLIENT_ERRNO;
        return 1;
    }

    ev_io_set(&(client->write_watcher), client->fd, EV_WRITE);
    ev_io_set(&(client->read_watcher), client->fd, EV_READ);
    ev_io_set(&(client->shutdown_watcher), client->fd, EV_READ);

    if (socket_type == SOCK_STREAM && connect(client->fd, addr, addrlen) < 0) {
        switch (errno) {
        case EINPROGRESS:
            ev_io_start(loop, &(client->write_watcher));
            client->state = CLIENT_CONNECTING;
            return 0;

        case ECONNREFUSED:
        case ENETUNREACH:
            client->state = CLIENT_FAILED;
            break;

        default:
            client->errnum = errno;
            client->state  = CLIENT_ERRNO;
            break;
        }
        return 1;
    }

    client->state        = CLIENT_CONNECTED;
    client->is_connected = 1;
    return 0;
}

int client_send(client_t* client, struct ev_loop* loop)
{
    ssize_t nsent;

    assert(client);
    if (!client) {
        return 1;
    }
    assert(loop);
    if (!loop) {
        return 1;
    }
    if (client->state != CLIENT_CONNECTED) {
        return 1;
    }

    if (client->is_stream && !client->sent_length) {
        uint16_t length = htons(client->query->len);

        if (client->have_to_addr)
            nsent = sendto(client->fd, &length, 2, 0, (struct sockaddr*)&(client->to_addr), client->to_addrlen);
        else
            nsent = sendto(client->fd, &length, 2, 0, 0, 0);
        if (nsent < 0) {
            switch (errno) {
            case EAGAIN:
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
                ev_io_start(loop, &(client->write_watcher));
                client->state = CLIENT_SENDING;
                return 0;

            default:
                break;
            }

            client->errnum = errno;
            client->state  = errno == ECONNRESET ? CLIENT_FAILED : CLIENT_ERRNO;
            return 1;
        } else if (nsent != 2) {
            client->errnum = ENOBUFS;
            client->state  = CLIENT_FAILED;
            return 1;
        }

        client->sent_length = 1;
    }

    if (client->have_to_addr)
        nsent = sendto(client->fd, core_query_raw(client->query), client->query->len, 0, (struct sockaddr*)&(client->to_addr), client->to_addrlen);
    else
        nsent = sendto(client->fd, core_query_raw(client->query), client->query->len, 0, 0, 0);
    if (nsent < 0) {
        switch (errno) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            ev_io_start(loop, &(client->write_watcher));
            client->state = CLIENT_SENDING;
            return 0;

        default:
            break;
        }

        client->errnum = errno;
        client->state  = errno == ECONNRESET ? CLIENT_FAILED : CLIENT_ERRNO;
        return 1;
    }

    if (nsent < client->query->len) {
        client->sent = nsent;
        ev_io_start(loop, &(client->write_watcher));
        client->state = CLIENT_SENDING;
        return 0;
    }

    if (client->skip_reply) {
        client->state = CLIENT_SUCCESS;
        return 0;
    }

    ev_io_start(loop, &(client->read_watcher));
    client->state = CLIENT_RECIVING;
    return 0;
}

int client_reuse(client_t* client, core_query_t* query)
{
    assert(client);
    if (!client) {
        return 1;
    }
    assert(query);
    if (!query) {
        return 1;
    }
    if (client->state != CLIENT_SUCCESS) {
        return 1;
    }

    if (client->query)
        core_query_free(client->query);
    client->query       = query;
    client->sent        = 0;
    client->recv        = 0;
    client->state       = CLIENT_CONNECTED;
    client->sent_length = 0;

    return 0;
}

int client_close(client_t* client, struct ev_loop* loop)
{
    assert(client);
    if (!client) {
        return 1;
    }
    assert(loop);
    if (!loop) {
        return 1;
    }

    switch (client->state) {
    case CLIENT_CONNECTING:
    case CLIENT_SENDING:
    case CLIENT_RECIVING:
        ev_io_stop(loop, &(client->write_watcher));
        ev_io_stop(loop, &(client->read_watcher));
        break;

    case CLIENT_CLOSING:
        return 0;

    default:
        break;
    }

    if (client->have_fd) {
        if (client->is_connected) {
            client->is_connected = 0;
            if (!shutdown(client->fd, SHUT_RDWR)) {
                ev_io_start(loop, &(client->shutdown_watcher));
                client->state = CLIENT_CLOSING;
                return 0;
            }
        }
        close(client->fd);
        client->have_fd = 0;
    }
    client->state = CLIENT_CLOSED;

    return 0;
}

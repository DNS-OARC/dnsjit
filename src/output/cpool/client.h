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

#include "core/query.h"

#ifndef __dnsjit_output_cpool_client_h
#define __dnsjit_output_cpool_client_h

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>

typedef enum client_state client_state_t;
enum client_state {
    CLIENT_NEW = 0,

    CLIENT_CONNECTING,
    CLIENT_CONNECTED,
    CLIENT_SENDING,
    CLIENT_RECIVING,
    CLIENT_CLOSING,

    CLIENT_SUCCESS,
    CLIENT_FAILED,
    CLIENT_ERROR,
    CLIENT_ERRNO,

    CLIENT_ABORTED,
    CLIENT_CLOSED
};

typedef struct client client_t;
typedef void (*client_callback_t)(client_t* client, struct ev_loop* loop);
struct client {
    unsigned short have_to_addr : 1;
    unsigned short have_from_addr : 1;
    unsigned short have_fd : 1;
    unsigned short is_connected : 1;
    unsigned short skip_reply : 1;
    unsigned short is_dgram : 1;
    unsigned short is_stream : 1;
    unsigned short sent_length : 1;
    unsigned short always_read : 1;

    ev_tstamp start;
    client_t* next;
    client_t* prev;

    int               fd;
    core_query_t*     query;
    ev_io             write_watcher;
    ev_io             read_watcher;
    ev_io             shutdown_watcher;
    client_callback_t callback;
    client_state_t    state;
    int               errnum;
    size_t            sent;
    size_t            recv;

    struct sockaddr_storage to_addr;
    socklen_t               to_addrlen;
    struct sockaddr_storage from_addr;
    socklen_t               from_addrlen;

    size_t   recvbuf_size;
    char*    recvbuf;
    ssize_t  nrecv;
    uint64_t dst_id;
};

client_t* client_new(core_query_t* query, client_callback_t callback);
void client_free(client_t* client);

client_t* client_next(client_t* client);
client_t* client_prev(client_t* client);
int client_fd(const client_t* client);
const core_query_t* client_query(const client_t* client);
client_state_t client_state(const client_t* client);
int client_is_connected(const client_t* client);
int client_errno(const client_t* client);
ev_tstamp client_start(const client_t* client);
int client_is_dgram(const client_t* client);
int client_is_stream(const client_t* client);
int client_set_next(client_t* client, client_t* next);
int client_set_prev(client_t* client, client_t* prev);
int client_set_start(client_t* client, ev_tstamp start);
int client_set_skip_reply(client_t* client);
core_query_t* client_release_query(client_t* client);

int client_set_recvbuf_size(client_t* client, size_t recvbuf_size);

int client_connect(client_t* client, int ipproto, const struct sockaddr* addr, socklen_t addlen, struct ev_loop* loop);
int client_send(client_t* client, struct ev_loop* loop);
int client_reuse(client_t* client, core_query_t* query);
int client_close(client_t* client, struct ev_loop* loop);

#endif

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

#include "sllq/sllq.h"
#include "output/cpool/client.h"
#include "core/log.h"

#ifndef __dnsjit_output_cpool_client_pool_h
#define __dnsjit_output_cpool_client_pool_h

#include <pthread.h>
#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef enum client_pool_sendas client_pool_sendas_t;
enum client_pool_sendas {
    CLIENT_POOL_SENDAS_ORIGINAL = 0,
    CLIENT_POOL_SENDAS_UDP      = 1,
    CLIENT_POOL_SENDAS_TCP      = 2
};

typedef enum client_pool_state client_pool_state_t;
enum client_pool_state {
    CLIENT_POOL_INACTIVE = 0,
    CLIENT_POOL_RUNNING,
    CLIENT_POOL_STOPPED,
    CLIENT_POOL_ERROR
};

typedef struct client_pool client_pool_t;
struct client_pool {
    client_pool_t* next;

    unsigned short have_queued_queries : 1;
    unsigned short is_stopping : 1;
    unsigned short client_skip_reply : 1;
    unsigned short dry_run : 1;

    client_pool_state_t state;
    pthread_t           thread_id;

    struct ev_loop* ev_loop;
    sllq_t          queries;
    query_t*        query;
    ev_async        notify_query;
    ev_async        notify_stop;
    ev_timer        timeout;
    ev_timer        retry;

    client_t* client_list_first;
    client_t* client_list_last;
    size_t    clients;
    size_t    max_clients;
    ev_tstamp client_ttl;

    struct addrinfo* addrinfo;

    client_t* reuse_client_list;
    size_t    reuse_clients;
    size_t    max_reuse_clients;

    client_pool_sendas_t sendas;

    log_t* _log;
};

client_pool_t* client_pool_new(const char* host, const char* port, size_t queue_size);
void client_pool_free(client_pool_t* client_pool);
int client_pool_start(client_pool_t* client_pool);
int client_pool_stop(client_pool_t* client_pool);
int client_pool_query(client_pool_t* client_pool, query_t* query);

#endif

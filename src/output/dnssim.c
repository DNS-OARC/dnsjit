/*
 * Copyright (c) 2019, CZ.NIC, z.s.p.o.
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

#include "output/dnssim.h"
#include "core/assert.h"
#include "core/object/ip.h"
#include "core/object/ip6.h"
#include "core/object/payload.h"

typedef struct _output_dnssim {
    output_dnssim_t pub;

    output_dnssim_transport_t transport;
    uv_loop_t loop;
    struct sockaddr_storage target;

    void (*create_request)(output_dnssim_t*, output_dnssim_client_t*,
        core_object_payload_t*);
} _output_dnssim_t;

typedef struct _output_dnssim_query _output_dnssim_query_t;
struct _output_dnssim_query {
    _output_dnssim_query_t* qry_prev;
    output_dnssim_transport_t transport;
};

typedef struct _output_dnssim_query_udp {
    _output_dnssim_query_t qry;
    uv_udp_t* handle;
    uv_buf_t buf;
    //uv_timer_t* qry_retransmit;
} _output_dnssim_query_udp_t;

typedef struct _output_dnssim_request {
    _output_dnssim_query_t* qry;
    output_dnssim_client_t* client;
    core_object_payload_t* payload;
    // TODO time start
    //uv_timer_t req_timeout;
} _output_dnssim_request_t;

static core_log_t _log = LOG_T_INIT("output.dnssim");
static output_dnssim_t _defaults = {
    LOG_T_INIT_OBJ("output.dnssim"),
    OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY, 0, 0
};
static output_dnssim_client_t _client_defaults = {
    0, 0, 0,
    0.0, 0.0, 0.0
};

// forward declarations
static void _close_query_udp(_output_dnssim_query_udp_t* qry);

core_log_t* output_dnssim_log()
{
    return &_log;
}

#define _self ((_output_dnssim_t*)self)


/*** request/query ***/
static void _maybe_free_request(_output_dnssim_request_t* req)
{
    if (req->qry == NULL) {
        free(req);
        mldebug("req freed");
    }
    // TODO optionally, free payload
}

static void _close_query(_output_dnssim_query_t* qry)
{
    switch(qry->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
        _close_query_udp((_output_dnssim_query_udp_t*)qry);
        break;
    default:
        mlnotice("failed to close query: unsupported transport");
        break;
    }
}

static void _close_request(_output_dnssim_request_t* req)
{
    // finish any ongoing queries
    _output_dnssim_query_t* qry = req->qry;
    while (qry != NULL) {
        _close_query(qry);
        qry = qry->qry_prev;
    }
    _maybe_free_request(req);
}


/*** UDP dnssim ***/
static void _uv_udp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
}

static void _uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
    const struct sockaddr* addr, unsigned flags)
{
	if (nread > 0) {
		printf("Received: %d\n", nread);
		//for (int i = 0; i < nread; ++i) {
		//	printf("%c", buf->base[i]);
		//}
		//printf("\n");
		uv_udp_recv_stop(handle);
	}

	if (buf->base != NULL) {
		free(buf->base);
	}
}

static void _close_query_udp_cb(uv_handle_t* handle)
{
    _output_dnssim_request_t* req = (_output_dnssim_request_t*)handle->data;
    _output_dnssim_query_t* qry = req->qry;
    _output_dnssim_query_t* parent_qry = req->qry;
    _output_dnssim_query_udp_t* udp_qry;

    for (;;) {  // find the query the handle belongs to
        if (qry->transport == OUTPUT_DNSSIM_TRANSPORT_UDP) {
            udp_qry = (_output_dnssim_query_udp_t*)qry;
            if (udp_qry->handle == (uv_udp_t*)handle) {
                free(udp_qry->handle);

                // free and remove from query list
                if (req->qry == qry) {
                    req->qry = qry->qry_prev;
                    _maybe_free_request(req);
                } else {
                    parent_qry->qry_prev = qry->qry_prev;
                }
                free(qry);
                mldebug("udp query freed");
                return;
            }
        }
        if (qry->qry_prev == NULL) {
            mlwarning("failed to free udp_query memory");
            return;
        }
        parent_qry = qry;
        qry = qry->qry_prev;
    }
}

static void _close_query_udp(_output_dnssim_query_udp_t* qry)
{
    uv_close((uv_handle_t*)qry->handle, _close_query_udp_cb);
}

static int _create_query_udp(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();

    int ret;
    _output_dnssim_query_udp_t* qry;

    lfatal_oom(qry = malloc(sizeof(_output_dnssim_query_udp_t)));
    lfatal_oom(qry->handle = malloc(sizeof(uv_udp_t)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_UDP;
    qry->qry.qry_prev = req->qry;
    qry->buf = uv_buf_init((char*)req->payload->payload, req->payload->len);
    ret = uv_udp_init(&_self->loop, qry->handle);
    if (ret != 0) {
        lwarning("failed to init uv_udp_t");
        goto failure;
    }
    qry->handle->data = (void*)req;

    ret = uv_udp_try_send(qry->handle, &qry->buf, 1, (struct sockaddr*)&_self->target);
    if (ret < 0) {
        lwarning("failed to send udp packet: %s", uv_strerror(ret));
        goto failure;
    }
    req->qry = (_output_dnssim_query_t*)qry;

    // TODO IPv4
    struct sockaddr_in6 src;
    int addr_len = sizeof(src);
    uv_udp_getsockname(qry->handle, (struct sockaddr*)&src, &addr_len);
    ldebug("sent udp from port: %d", ntohs(src.sin6_port));

    // TODO listen for reply

    return 0;
failure:
    free(qry->handle);
    free(qry);
    return ret;
}

static void _create_request_udp(output_dnssim_t* self, output_dnssim_client_t* client,
    core_object_payload_t* payload)
{
    mlassert_self();

    int ret;
    _output_dnssim_request_t* req;

    client->req_total++;

    lfatal_oom(req = malloc(sizeof(_output_dnssim_request_t)));

    req->client = client;
    req->payload = payload;
    req->qry = NULL;

    ret = _create_query_udp(self, req);
    if (ret != 0) {
        goto failure;
    }

    // TODO move to proper place
    _close_request(req);

    return;
failure:
    self->dropped_pkts++;
    free(req);
    return;
}

/*** dnssim functions ***/
output_dnssim_t* output_dnssim_new(size_t max_clients)
{
    output_dnssim_t* self;
    int ret;

    mlfatal_oom(self = malloc(sizeof(_output_dnssim_t)));
    *self = _defaults;

    _self->transport = OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY;
    _self->create_request = _create_request_udp;

    lfatal_oom(self->client_arr = calloc(
        max_clients, sizeof(output_dnssim_client_t)));
    for (int i = 0; i < self->max_clients; i++) {
        *self->client_arr = _client_defaults;
    }
    self->max_clients = max_clients;

    ret = uv_loop_init(&_self->loop);
    if (ret < 0) {
        lfatal("failed to initialize uv_loop (%s)", uv_strerror(ret));
    }
    ldebug("initialized uv_loop");

    return self;
}

void output_dnssim_free(output_dnssim_t* self)
{
    mlassert_self();
    int ret;

    free(self->client_arr);

    ret = uv_loop_close(&_self->loop);
    if (ret < 0) {
        lcritical("failed to close uv_loop (%s)", uv_strerror(ret));
    } else {
        ldebug("closed uv_loop");
    }

    free(self);
}

ssize_t _extract_client(const core_object_t* obj) {
    ssize_t client;
    uint8_t* ip;

    switch (obj->obj_type) {
    case CORE_OBJECT_IP:
        ip = ((core_object_ip_t*)obj)->dst;
        break;
    case CORE_OBJECT_IP6:
        ip = ((core_object_ip6_t*)obj)->dst;
        break;
    default:
        return -1;
    }

    client = ip[3];
    client += (ip[2] << 8);
    client += (ip[1] << 16);
    client += (ip[0] << 24);

    return client;
}

static void _receive(output_dnssim_t* self, const core_object_t* obj)
{
    mlassert_self();
    core_object_payload_t* payload;
    ssize_t client;

    /* get payload from packet */
    for (;;) {
        if (obj->obj_type == CORE_OBJECT_PAYLOAD) {
            payload = (core_object_payload_t*)obj;
            break;
        }
        if (obj->obj_prev == NULL) {
            self->dropped_pkts++;
            lwarning("packet droppped (missing payload object)");
            return;
        }
        obj = (const core_object_t*)obj->obj_prev;
    }

    /* extract client information from IP/IP6 layer */
    for (;;) {
        if (obj->obj_type == CORE_OBJECT_IP || obj->obj_type == CORE_OBJECT_IP6) {
            client = _extract_client(obj);
            break;
        }
        if (obj->obj_prev == NULL) {
            self->dropped_pkts++;
            lwarning("packet droppped (missing ip/ip6 object)");
            return;
        }
        obj = (const core_object_t*)obj->obj_prev;
    }

    if (client >= self->max_clients) {
        self->dropped_pkts++;
        lwarning("packet dropped (client exceeded max_clients)");
        return;
    }

    ldebug("client(c): %d", client);
    _self->create_request(self, &self->client_arr[client], payload);
}

core_receiver_t output_dnssim_receiver()
{
    return (core_receiver_t)_receive;
}

void output_dnssim_set_transport(output_dnssim_t* self, output_dnssim_transport_t tr) {
    mlassert_self();

    switch(tr) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY:
        _self->create_request = _create_request_udp;
        linfo("transport set to UDP (no TCP fallback)");
        break;
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
    default:
        lfatal("unknown or unsupported transport");
        break;
    }

    _self->transport = tr;
}

int output_dnssim_target(output_dnssim_t* self, const char* ip, uint16_t port) {
    int ret;
    mlassert_self();
    lassert(ip, "ip is nil");
    lassert(port, "port is nil");

    ret = uv_ip6_addr(ip, port, (struct sockaddr_in6*)&_self->target);
    if (ret != 0) {
        lcritical("failed to parse IPv6 from \"%s\"", ip);
        return -1;
        // TODO IPv4 support
        //ret = uv_ip4_addr(ip, port, (struct sockaddr_in*)&_self->target);
        //if (ret != 0) {
        //    lcritical("failed to parse IP/IP6 from \"%s\"", ip);
        //    return -1;
        //}
    }

    linfo("set target to %s port %d", ip, port);
    return 0;
}

int output_dnssim_run_nowait(output_dnssim_t* self)
{
    mlassert_self();

    return uv_run(&_self->loop, UV_RUN_NOWAIT);
}

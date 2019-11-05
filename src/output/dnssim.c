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
#include "core/object/dns.h"

typedef struct _output_dnssim_source _output_dnssim_source_t;
struct _output_dnssim_source {
    _output_dnssim_source_t* next;
    struct sockaddr_storage addr;
};

typedef struct _output_dnssim {
    output_dnssim_t pub;

    output_dnssim_transport_t transport;
    uv_loop_t loop;
    struct sockaddr_storage target;
    _output_dnssim_source_t* source;

    uv_timer_t stats_timer;

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
    core_object_dns_t* dns_q;
    uint64_t created_at;
    uint64_t ended_at;
    uv_timer_t* timeout;
    uint8_t timeout_closing;
    uint8_t ongoing;
    output_dnssim_t* dnssim;
} _output_dnssim_request_t;

static core_log_t _log = LOG_T_INIT("output.dnssim");
static output_dnssim_t _defaults = {
    LOG_T_INIT_OBJ("output.dnssim"),
    0, 0, 0,
    NULL, NULL, NULL,
    0, 0, 0,
    2000
};
static output_dnssim_client_t _client_defaults = {
    0, 0, 0,
};
static output_dnssim_stats_t _stats_defaults = {
    NULL, NULL,
    NULL,
    0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// forward declarations
static void _close_query_udp(_output_dnssim_query_udp_t* qry);
static void _close_request_timeout_cb(uv_handle_t* handle);
static void _close_request_timeout(uv_timer_t* handle);

core_log_t* output_dnssim_log()
{
    return &_log;
}

#define _self ((_output_dnssim_t*)self)
#define _ERR_MALFORMED -2
#define _ERR_MSGID -3
#define _ERR_TC -4


/*** request/query ***/
static void _maybe_free_request(_output_dnssim_request_t* req)
{
    if (req->qry == NULL && req->timeout == NULL) {
        if (req->dnssim->free_after_use) {
            core_object_payload_free(req->payload);
            mldebug("payload freed");
        }
        core_object_dns_free(req->dns_q);
        free(req);
        mldebug("req freed");
    }
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
    if (req == NULL) {
        return;
    }
    if (req->ongoing) {
        req->ongoing = 0;
        req->dnssim->ongoing--;
    }
    if (req->timeout != NULL) {
        _close_request_timeout(req->timeout);
    }
    // finish any queries in flight
    _output_dnssim_query_t* qry = req->qry;
    while (qry != NULL) {
        _close_query(qry);
        qry = qry->qry_prev;
    }
    _maybe_free_request(req);
}

static void _close_request_timeout_cb(uv_handle_t* handle)
{
    _output_dnssim_request_t* req = (_output_dnssim_request_t*)handle->data;
    free(handle);
    mldebug("req timer freed");
    req->timeout = NULL;
    _close_request(req);
}

static void _close_request_timeout(uv_timer_t* handle)
{
    _output_dnssim_request_t* req = (_output_dnssim_request_t*)handle->data;

    if (!req->timeout_closing) {
        req->timeout_closing = 1;

        uint64_t latency = req->ended_at - req->created_at;
        mlassert(latency <= req->dnssim->timeout_ms, "invalid latency value");
        req->dnssim->stats_current->latency[latency]++;
        req->dnssim->stats_sum->latency[latency]++;

        uv_timer_stop(handle);
        uv_close((uv_handle_t*)handle, _close_request_timeout_cb);
    }
}


/*** UDP dnssim ***/
static int _process_udp_response(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf)
{
    _output_dnssim_request_t* req = (_output_dnssim_request_t*)handle->data;
    core_object_payload_t payload = CORE_OBJECT_PAYLOAD_INIT(NULL);
    core_object_dns_t dns_a = CORE_OBJECT_DNS_INIT(&payload);

    payload.payload = buf->base;
    payload.len = nread;

    dns_a.obj_prev = (core_object_t*)&payload;
    int ret = core_object_dns_parse_header(&dns_a);
    if (ret != 0) {
        mldebug("udp response malformed");
        return _ERR_MALFORMED;
    }
    if (dns_a.id != req->dns_q->id) {
        mldebug("udp response msgid mismatch %x(q) != %x(a)", req->dns_q->id, dns_a.id);
        return _ERR_MSGID;
    }
    if (dns_a.tc == 1) {
        mldebug("udp response has TC=1");
        return _ERR_TC;
    }

    req->ended_at = uv_now(&((_output_dnssim_t*)req->dnssim)->loop);
    if (req->ended_at > (req->created_at + req->dnssim->timeout_ms)) {
        req->ended_at = req->created_at + req->dnssim->timeout_ms;
    }

    req->client->answers++;
    req->dnssim->stats_sum->answers++;
    req->dnssim->stats_current->answers++;

    switch(dns_a.rcode) {
    case CORE_OBJECT_DNS_RCODE_NOERROR:
        req->client->noerror++;
        req->dnssim->stats_sum->rcode_noerror++;
        req->dnssim->stats_current->rcode_noerror++;
        break;
    case CORE_OBJECT_DNS_RCODE_FORMERR:
        req->dnssim->stats_sum->rcode_formerr++;
        req->dnssim->stats_current->rcode_formerr++;
        break;
    case CORE_OBJECT_DNS_RCODE_SERVFAIL:
        req->dnssim->stats_sum->rcode_servfail++;
        req->dnssim->stats_current->rcode_servfail++;
        break;
    case CORE_OBJECT_DNS_RCODE_NXDOMAIN:
        req->dnssim->stats_sum->rcode_nxdomain++;
        req->dnssim->stats_current->rcode_nxdomain++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTIMP:
        req->dnssim->stats_sum->rcode_notimp++;
        req->dnssim->stats_current->rcode_notimp++;
        break;
    case CORE_OBJECT_DNS_RCODE_REFUSED:
        req->dnssim->stats_sum->rcode_refused++;
        req->dnssim->stats_current->rcode_refused++;
        break;
    case CORE_OBJECT_DNS_RCODE_YXDOMAIN:
        req->dnssim->stats_sum->rcode_yxdomain++;
        req->dnssim->stats_current->rcode_yxdomain++;
        break;
    case CORE_OBJECT_DNS_RCODE_YXRRSET:
        req->dnssim->stats_sum->rcode_yxrrset++;
        req->dnssim->stats_current->rcode_yxrrset++;
        break;
    case CORE_OBJECT_DNS_RCODE_NXRRSET:
        req->dnssim->stats_sum->rcode_nxrrset++;
        req->dnssim->stats_current->rcode_nxrrset++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTAUTH:
        req->dnssim->stats_sum->rcode_notauth++;
        req->dnssim->stats_current->rcode_notauth++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTZONE:
        req->dnssim->stats_sum->rcode_notzone++;
        req->dnssim->stats_current->rcode_notzone++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADVERS:
        req->dnssim->stats_sum->rcode_badvers++;
        req->dnssim->stats_current->rcode_badvers++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADKEY:
        req->dnssim->stats_sum->rcode_badkey++;
        req->dnssim->stats_current->rcode_badkey++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADTIME:
        req->dnssim->stats_sum->rcode_badtime++;
        req->dnssim->stats_current->rcode_badtime++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADMODE:
        req->dnssim->stats_sum->rcode_badmode++;
        req->dnssim->stats_current->rcode_badmode++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADNAME:
        req->dnssim->stats_sum->rcode_badname++;
        req->dnssim->stats_current->rcode_badname++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADALG:
        req->dnssim->stats_sum->rcode_badalg++;
        req->dnssim->stats_current->rcode_badalg++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADTRUNC:
        req->dnssim->stats_sum->rcode_badtrunc++;
        req->dnssim->stats_current->rcode_badtrunc++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADCOOKIE:
        req->dnssim->stats_sum->rcode_badcookie++;
        req->dnssim->stats_current->rcode_badcookie++;
        break;
    default:
        req->dnssim->stats_sum->rcode_other++;
        req->dnssim->stats_current->rcode_other++;
    }

    _close_request(req);
    return 0;
}

static void _query_udp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    mlfatal_oom(buf->base = malloc(suggested_size));
    buf->len = suggested_size;
}

static void _query_udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
    const struct sockaddr* addr, unsigned flags)
{
    if (nread > 0) {
        mldebug("udp recv: %d", nread);

        // TODO handle TC=1
        _process_udp_response(handle, nread, buf);
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
                mldebug("freed udp query %p", qry);
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
    int ret;

    ret = uv_udp_recv_stop(qry->handle);
    if (ret < 0) {
        mldebug("failed uv_udp_recv_stop(): %s", uv_strerror(ret));
    }

    uv_close((uv_handle_t*)qry->handle, _close_query_udp_cb);
}

static int _create_query_udp(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();

    int ret;
    _output_dnssim_query_udp_t* qry;
    core_object_payload_t* payload = (core_object_payload_t*)req->dns_q->obj_prev;

    lfatal_oom(qry = malloc(sizeof(_output_dnssim_query_udp_t)));
    lfatal_oom(qry->handle = malloc(sizeof(uv_udp_t)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_UDP;
    qry->qry.qry_prev = req->qry;
    qry->buf = uv_buf_init((char*)payload->payload, payload->len);
    ret = uv_udp_init(&_self->loop, qry->handle);
    if (ret < 0) {
        lwarning("failed to init uv_udp_t");
        goto failure;
    }
    qry->handle->data = (void*)req;
    req->qry = (_output_dnssim_query_t*)qry;

    // bind to IP address
    if (_self->source != NULL) {
        ret = uv_udp_bind(qry->handle, (struct sockaddr*)&_self->source->addr, 0);
        if (ret < 0) {
            lwarning("failed to bind to address: %s", uv_strerror(ret));
            return ret;
        }
        _self->source = _self->source->next;
    }

    ret = uv_udp_try_send(qry->handle, &qry->buf, 1, (struct sockaddr*)&_self->target);
    if (ret < 0) {
        lwarning("failed to send udp packet: %s", uv_strerror(ret));
        return ret;
    }

    // TODO IPv4
    struct sockaddr_in6 src;
    int addr_len = sizeof(src);
    uv_udp_getsockname(qry->handle, (struct sockaddr*)&src, &addr_len);
    ldebug("sent udp from port: %d", ntohs(src.sin6_port));

    // listen for reply
    ret = uv_udp_recv_start(qry->handle, _query_udp_alloc_cb, _query_udp_recv_cb);
    if (ret < 0) {
        lwarning("failed uv_udp_recv_start(): %s", uv_strerror(ret));
        return ret;
    }

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

    lfatal_oom(req = malloc(sizeof(_output_dnssim_request_t)));
    memset(req, 0, sizeof(_output_dnssim_request_t));
    req->dnssim = self;
    req->client = client;
    req->payload = payload;
    req->dns_q = core_object_dns_new();
    req->dns_q->obj_prev = (core_object_t*)req->payload;
    req->ongoing = 1;
    req->dnssim->ongoing++;

    ret = core_object_dns_parse_header(req->dns_q);
    if (ret != 0) {
        ldebug("discarded malformed dns query: couldn't parse header");
        goto failure;
    }

    req->client->requests++;
    req->dnssim->stats_sum->requests++;
    req->dnssim->stats_current->requests++;

    ret = _create_query_udp(self, req);
    if (ret < 0) {
        goto failure;
    }

    req->created_at = uv_now(&_self->loop);
    req->ended_at = req->created_at + self->timeout_ms;
    lfatal_oom(req->timeout = malloc(sizeof(uv_timer_t)));
    ret = uv_timer_init(&_self->loop, req->timeout);
    req->timeout->data = req;
    if (ret < 0) {
        ldebug("failed uv_timer_init(): %s", uv_strerror(ret));
        free(req->timeout);
        req->timeout = NULL;
        goto failure;
    }
    ret = uv_timer_start(req->timeout, _close_request_timeout, self->timeout_ms, 0);
    if (ret < 0) {
        ldebug("failed uv_timer_start(): %s", uv_strerror(ret));
        goto failure;
    }

    return;
failure:
    self->discarded++;
    _close_request(req);
    return;
}

/*** dnssim functions ***/
output_dnssim_t* output_dnssim_new(size_t max_clients)
{
    output_dnssim_t* self;
    int ret;

    mlfatal_oom(self = malloc(sizeof(_output_dnssim_t)));
    *self = _defaults;

    lfatal_oom(self->stats_sum = malloc(sizeof(output_dnssim_stats_t)));
    *self->stats_sum = _stats_defaults;
    lfatal_oom(self->stats_sum->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    lfatal_oom(self->stats_current = malloc(sizeof(output_dnssim_stats_t)));
    *self->stats_current = _stats_defaults;
    lfatal_oom(self->stats_current->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    self->stats_first = self->stats_current;

    _self->source = NULL;
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
    _output_dnssim_source_t* source;
    _output_dnssim_source_t* first = _self->source;
    output_dnssim_stats_t* stats_prev;

    free(self->stats_sum->latency);
    free(self->stats_sum);
    do {
        stats_prev = self->stats_current->prev;
        free(self->stats_current->latency);
        free(self->stats_current);
        self->stats_current = stats_prev;
    } while (self->stats_current != NULL);

    if (_self->source != NULL) {
        // free cilcular linked list
        do {
            source = _self->source->next;
            free(_self->source);
            _self->source = source;
        } while (_self->source != first);
    }

    free(self->client_arr);

    ret = uv_loop_close(&_self->loop);
    if (ret < 0) {
        lcritical("failed to close uv_loop (%s)", uv_strerror(ret));
    } else {
        ldebug("closed uv_loop");
    }

    free(self);
}

uint32_t _extract_client(const core_object_t* obj) {
    uint32_t client;
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

    memcpy(&client, ip, sizeof(client));
    return client;
}

static void _receive(output_dnssim_t* self, const core_object_t* obj)
{
    mlassert_self();
    core_object_t* current = (core_object_t*)obj;
    core_object_payload_t* payload;
    uint32_t client;

    self->processed++;

    /* get payload from packet */
    for (;;) {
        if (current->obj_type == CORE_OBJECT_PAYLOAD) {
            payload = (core_object_payload_t*)current;
            break;
        }
        if (current->obj_prev == NULL) {
            self->discarded++;
            lwarning("packet discarded (missing payload object)");
            return;
        }
        current = (core_object_t*)current->obj_prev;
    }

    /* extract client information from IP/IP6 layer */
    for (;;) {
        if (current->obj_type == CORE_OBJECT_IP || current->obj_type == CORE_OBJECT_IP6) {
            client = _extract_client(current);
            break;
        }
        if (current->obj_prev == NULL) {
            self->discarded++;
            lwarning("packet discarded (missing ip/ip6 object)");
            return;
        }
        current = (core_object_t*)current->obj_prev;
    }

    if (self->free_after_use) {
        /* free all objects except payload */
        current = (core_object_t*)obj;
        core_object_t* parent = current;
        while (current != NULL) {
            parent = current;
            current = (core_object_t*)current->obj_prev;
            if (parent->obj_type != CORE_OBJECT_PAYLOAD) {
                core_object_free(parent);
            }
        }
    }

    if (client >= self->max_clients) {
        self->discarded++;
        lwarning("packet discarded (client exceeded max_clients)");
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
        lnotice("transport set to UDP (no TCP fallback)");
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

    lnotice("set target to %s port %d", ip, port);
    return 0;
}

int output_dnssim_bind(output_dnssim_t* self, const char* ip) {
    int ret;
    mlassert_self();
    lassert(ip, "ip is nil");

    _output_dnssim_source_t* source;
    lfatal_oom(source = malloc(sizeof(_output_dnssim_source_t)));

    ret = uv_ip6_addr(ip, 0, (struct sockaddr_in6*)&source->addr);
    if (ret != 0) {
        lfatal("failed to parse IPv6 from \"%s\"", ip);
        return -1;
        // TODO IPv4 support
    }

    if (_self->source == NULL) {
        source->next = source;
        _self->source = source;
    } else {
        source->next = _self->source->next;
        _self->source->next = source;
    }

    lnotice("bind to source address %s", ip);
    return 0;
}

int output_dnssim_run_nowait(output_dnssim_t* self)
{
    mlassert_self();

    return uv_run(&_self->loop, UV_RUN_NOWAIT);
}

static void _stats_timer_cb(uv_timer_t* handle)
{
    output_dnssim_t* self = (output_dnssim_t*)handle->data;
    lnotice("processed:%10ld; answers:%10ld; discarded:%10ld; ongoing:%10ld",
        self->processed, self->stats_sum->answers, self->discarded,
        self->ongoing);

    output_dnssim_stats_t* stats_next;
    lfatal_oom(stats_next = malloc(sizeof(output_dnssim_stats_t)));
    *stats_next = _stats_defaults;
    lfatal_oom(stats_next->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    stats_next->ongoing = self->ongoing;
    stats_next->prev = self->stats_current;
    self->stats_current->next = stats_next;
    self->stats_current = stats_next;
}

void output_dnssim_stats_collect(output_dnssim_t* self, uint64_t interval_ms)
{
    int ret;
    mlassert_self();

    _self->stats_timer.data = (void*)self;
    ret = uv_timer_init(&_self->loop, &_self->stats_timer);
    if (ret < 0) {
        lcritical("failed to init stats_timer: %s", uv_strerror(ret));
        return;
    }
    ret = uv_timer_start(&_self->stats_timer, _stats_timer_cb, interval_ms, interval_ms);
    if (ret < 0) {
        lcritical("failed to start stats_timer: %s", uv_strerror(ret));
        return;
    }
}

void output_dnssim_stats_finish(output_dnssim_t* self)
{
    int ret;
    mlassert_self();

    ret = uv_timer_stop(&_self->stats_timer);
    if (ret < 0) {
        lcritical("failed to stop stats_timer: %s", uv_strerror(ret));
        return;
    }
    uv_close((uv_handle_t*)&_self->stats_timer, NULL);
}

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
#include "output/dnssim.h"

#include "output/dnssim/udp.c"
#include "output/dnssim/tcp.c"

uint64_t _now_ms()
{
#if HAVE_CLOCK_NANOSLEEP
    struct timespec ts;
    uint64_t now_ms;
    if (clock_gettime(CLOCK_REALTIME, &ts)) {
        mlfatal("clock_gettime()");
    }
    now_ms = ts.tv_sec * 1000;
    now_ms += ts.tv_nsec / 1000000;
    return now_ms;
#else
    mlfatal("clock_gettime() not available");
#endif
}

core_log_t* output_dnssim_log()
{
    return &_log;
}


/*** request/query ***/
static void _maybe_free_request(_output_dnssim_request_t* req)
{
    if (req->qry == NULL && req->timeout == NULL) {
        if (req->dnssim->free_after_use) {
            core_object_payload_free(req->payload);
        }
        core_object_dns_free(req->dns_q);
        free(req);
    }
}

static void _close_query(_output_dnssim_query_t* qry)
{
    switch(qry->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
        _close_query_udp((_output_dnssim_query_udp_t*)qry);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        _close_query_tcp((_output_dnssim_query_tcp_t*)qry);
        break;
    default:
        mlfatal("invalid query transport");
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
        qry = qry->next;
    }
    _maybe_free_request(req);
}

static void _close_request_timeout_cb(uv_handle_t* handle)
{
    _output_dnssim_request_t* req = (_output_dnssim_request_t*)handle->data;
    free(handle);
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

static void _request_answered(_output_dnssim_request_t* req, core_object_dns_t* msg)
{
    req->ended_at = uv_now(&((_output_dnssim_t*)req->dnssim)->loop);
    if (req->ended_at > (req->created_at + req->dnssim->timeout_ms)) {
        req->ended_at = req->created_at + req->dnssim->timeout_ms;
    }

    req->dnssim->stats_sum->answers++;
    req->dnssim->stats_current->answers++;

    switch(msg->rcode) {
    case CORE_OBJECT_DNS_RCODE_NOERROR:
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
}


/* Common network-related stuff. */
static void _uv_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    mlfatal_oom(buf->base = malloc(suggested_size));
    buf->len = suggested_size;
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

    lfatal_oom(_self->client_arr = calloc(
        max_clients, sizeof(_output_dnssim_client_t)));
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

    free(_self->client_arr);

    ret = uv_loop_close(&_self->loop);
    if (ret < 0) {  // TODO wait for TCP connections to close
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
    _self->create_request(self, &_self->client_arr[client], payload);
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
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        _self->create_request = _create_request_tcp;
        lnotice("transport set to TCP");
        break;
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
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
    uint64_t now_ms = _now_ms();
    output_dnssim_t* self = (output_dnssim_t*)handle->data;
    lnotice("total processed:%10ld; answers:%10ld; discarded:%10ld; ongoing:%10ld",
        self->processed, self->stats_sum->answers, self->discarded,
        self->ongoing);

    output_dnssim_stats_t* stats_next;
    lfatal_oom(stats_next = malloc(sizeof(output_dnssim_stats_t)));
    *stats_next = _stats_defaults;
    lfatal_oom(stats_next->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    self->stats_current->until_ms = now_ms;
    stats_next->since_ms = now_ms;

    stats_next->ongoing = self->ongoing;
    stats_next->prev = self->stats_current;
    self->stats_current->next = stats_next;
    self->stats_current = stats_next;
}

void output_dnssim_stats_collect(output_dnssim_t* self, uint64_t interval_ms)
{
    int ret;
    uint64_t now_ms = _now_ms();
    mlassert_self();

    if (self->stats_interval_ms != 0) {
        lfatal("statistics collection has already started!");
    }
    self->stats_interval_ms = interval_ms;

    self->stats_sum->since_ms = now_ms;
    self->stats_current->since_ms = now_ms;

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
    uint64_t now_ms = _now_ms();
    mlassert_self();

    self->stats_sum->until_ms = now_ms;
    self->stats_current->until_ms = now_ms;

    ret = uv_timer_stop(&_self->stats_timer);
    if (ret < 0) {
        lcritical("failed to stop stats_timer: %s", uv_strerror(ret));
        return;
    }
    uv_close((uv_handle_t*)&_self->stats_timer, NULL);
}

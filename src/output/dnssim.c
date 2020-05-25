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

#include "output/dnssim.h"
#include "output/dnssim/internal.h"
#include "output/dnssim/ll.h"
#include "core/assert.h"
#include "core/object/ip.h"
#include "core/object/ip6.h"

#include <gnutls/gnutls.h>
#include <string.h>

static core_log_t _log = LOG_T_INIT("output.dnssim");

static uint64_t _now_ms()
{
#if HAVE_CLOCK_NANOSLEEP
    struct timespec ts;
    uint64_t        now_ms;
    if (clock_gettime(CLOCK_REALTIME, &ts)) {
        mlfatal("clock_gettime()");
    }
    now_ms = ts.tv_sec * 1000;
    now_ms += ts.tv_nsec / 1000000;
    return now_ms;
#else
    mlfatal("clock_gettime() not available");
    return 0;
#endif
}

core_log_t* output_dnssim_log()
{
    return &_log;
}

output_dnssim_t* output_dnssim_new(size_t max_clients)
{
    output_dnssim_t* self;
    int              ret, i;

    mlfatal_oom(self = calloc(1, sizeof(_output_dnssim_t)));
    self->handshake_timeout_ms = 5000;
    self->idle_timeout_ms      = 10000;
    output_dnssim_timeout_ms(self, 2000);

    _self->source    = NULL;
    _self->transport = OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY;

    self->max_clients = max_clients;
    lfatal_oom(_self->client_arr = calloc(max_clients, sizeof(_output_dnssim_client_t)));

    for (i = 0; i < max_clients; ++i) {
        _self->client_arr[i].dnssim = self;
    }

    ret = gnutls_certificate_allocate_credentials(&_self->tls_cred);
    if (ret < 0)
        lfatal("failed to allocated TLS credentials (%s)", gnutls_strerror(ret));

    ret = uv_loop_init(&_self->loop);
    if (ret < 0)
        lfatal("failed to initialize uv_loop (%s)", uv_strerror(ret));
    ldebug("initialized uv_loop");

    return self;
}

void output_dnssim_free(output_dnssim_t* self)
{
    mlassert_self();
    int                      ret;
    _output_dnssim_source_t* source;
    _output_dnssim_source_t* first = _self->source;
    output_dnssim_stats_t*   stats_prev;

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

    for (int i = 0; i < self->max_clients; ++i) {
        if (_self->client_arr[i].tls_ticket.size != 0) {
            gnutls_free(_self->client_arr[i].tls_ticket.data);
        }
    }
    free(_self->client_arr);

    ret = uv_loop_close(&_self->loop);
    if (ret < 0) {
        lcritical("failed to close uv_loop (%s)", uv_strerror(ret));
    } else {
        ldebug("closed uv_loop");
    }

    gnutls_certificate_free_credentials(_self->tls_cred);
    if (_self->tls_priority != NULL) {
        gnutls_priority_deinit(*_self->tls_priority);
        free(_self->tls_priority);
    }

    free(self);
}

static uint32_t _extract_client(const core_object_t* obj)
{
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
    core_object_t*         current = (core_object_t*)obj;
    core_object_payload_t* payload;
    uint32_t               client;

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
        current               = (core_object_t*)obj;
        core_object_t* parent = current;
        while (current != NULL) {
            parent  = current;
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
    _output_dnssim_create_request(self, &_self->client_arr[client], payload);
}

core_receiver_t output_dnssim_receiver()
{
    return (core_receiver_t)_receive;
}

void output_dnssim_set_transport(output_dnssim_t* self, output_dnssim_transport_t tr)
{
    mlassert_self();

    switch (tr) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY:
        lnotice("transport set to UDP (no TCP fallback)");
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        lnotice("transport set to TCP");
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
        lnotice("transport set to TLS");
        break;
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
    default:
        lfatal("unknown or unsupported transport");
        break;
    }

    _self->transport = tr;
}

int output_dnssim_target(output_dnssim_t* self, const char* ip, uint16_t port)
{
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

int output_dnssim_bind(output_dnssim_t* self, const char* ip)
{
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
        source->next  = source;
        _self->source = source;
    } else {
        source->next        = _self->source->next;
        _self->source->next = source;
    }

    lnotice("bind to source address %s", ip);
    return 0;
}

int output_dnssim_tls_priority(output_dnssim_t* self, const char* priority)
{
    mlassert_self();
    lassert(priority, "priority is nil");

    if (_self->tls_priority != NULL) {
        gnutls_priority_deinit(*_self->tls_priority);
        free(_self->tls_priority);
    }
    lfatal_oom(_self->tls_priority = malloc(sizeof(gnutls_priority_t)));

    int ret = gnutls_priority_init(_self->tls_priority, priority, NULL);
    if (ret < 0) {
        lfatal("failed to initialize TLS priority cache: %s", gnutls_strerror(ret));
    } else {
        lnotice("GnuTLS priority set: %s", priority);
    }

    return 0;
}

int output_dnssim_run_nowait(output_dnssim_t* self)
{
    mlassert_self();

    return uv_run(&_self->loop, UV_RUN_NOWAIT);
}

void output_dnssim_timeout_ms(output_dnssim_t* self, uint64_t timeout_ms)
{
    mlassert_self();
    lassert(timeout_ms > 0, "timeout must be greater than 0");

    if (self->stats_sum != NULL) {
        free(self->stats_sum->latency);
        free(self->stats_sum);
        self->stats_sum = 0;
    }
    if (self->stats_current != NULL) {
        output_dnssim_stats_t* stats_prev;
        do {
            stats_prev = self->stats_current->prev;
            free(self->stats_current->latency);
            free(self->stats_current);
            self->stats_current = stats_prev;
        } while (self->stats_current != NULL);
    }

    self->timeout_ms = timeout_ms;

    lfatal_oom(self->stats_sum = calloc(1, sizeof(output_dnssim_stats_t)));
    lfatal_oom(self->stats_sum->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    lfatal_oom(self->stats_current = calloc(1, sizeof(output_dnssim_stats_t)));
    lfatal_oom(self->stats_current->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    self->stats_first = self->stats_current;
}

static void _on_stats_timer_tick(uv_timer_t* handle)
{
    uint64_t         now_ms = _now_ms();
    output_dnssim_t* self;
    mlassert(handle, "handle is nil");
    self = (output_dnssim_t*)handle->data;
    mlassert_self();
    lassert(self->stats_sum, "stats_sum is nil");
    lassert(self->stats_current, "stats_current is nil");

    lnotice("total processed:%10ld; answers:%10ld; discarded:%10ld; ongoing:%10ld",
            self->processed, self->stats_sum->answers, self->discarded, self->ongoing);

    output_dnssim_stats_t* stats_next;
    lfatal_oom(stats_next = calloc(1, sizeof(output_dnssim_stats_t)));
    lfatal_oom(stats_next->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    self->stats_current->until_ms = now_ms;
    stats_next->since_ms          = now_ms;
    stats_next->conn_active       = self->stats_current->conn_active;

    stats_next->ongoing       = self->ongoing;
    stats_next->prev          = self->stats_current;
    self->stats_current->next = stats_next;
    self->stats_current       = stats_next;
}

void output_dnssim_stats_collect(output_dnssim_t* self, uint64_t interval_ms)
{
    uint64_t now_ms = _now_ms();
    mlassert_self();
    lassert(self->stats_sum, "stats_sum is nil");
    lassert(self->stats_current, "stats_current is nil");

    if (self->stats_interval_ms != 0) {
        lfatal("statistics collection has already started!");
    }
    self->stats_interval_ms = interval_ms;

    self->stats_sum->since_ms     = now_ms;
    self->stats_current->since_ms = now_ms;

    _self->stats_timer.data = (void*)self;
    uv_timer_init(&_self->loop, &_self->stats_timer);
    uv_timer_start(&_self->stats_timer, _on_stats_timer_tick, interval_ms, interval_ms);
}

void output_dnssim_stats_finish(output_dnssim_t* self)
{
    uint64_t now_ms = _now_ms();
    mlassert_self();
    lassert(self->stats_sum, "stats_sum is nil");
    lassert(self->stats_current, "stats_current is nil");

    self->stats_sum->until_ms     = now_ms;
    self->stats_current->until_ms = now_ms;

    uv_timer_stop(&_self->stats_timer);
    uv_close((uv_handle_t*)&_self->stats_timer, NULL);
}

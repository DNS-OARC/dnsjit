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

#include "output/dnssim/common.c"
#include "output/dnssim/udp.c"
#include "output/dnssim/tcp.c"


core_log_t* output_dnssim_log()
{
    return &_log;
}

output_dnssim_t* output_dnssim_new(size_t max_clients)
{
    output_dnssim_t* self;
    int ret;

    mlfatal_oom(self = calloc(1, sizeof(_output_dnssim_t)));
    self->handshake_timeout_ms = 5000;
    output_dnssim_timeout_ms(self, 2000);

    _self->source = NULL;
    _self->transport = OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY;

    self->max_clients = max_clients;
    lfatal_oom(_self->client_arr = calloc(
        max_clients, sizeof(_output_dnssim_client_t)));
    for (int i=0; i < max_clients; ++i)
        _self->client_arr[i].dnssim = self;

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
    if (ret < 0) {
        lcritical("failed to close uv_loop (%s)", uv_strerror(ret));
    } else {
        ldebug("closed uv_loop");
    }

    free(self);
}

static uint32_t _extract_client(const core_object_t* obj) {
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
    _create_request(self, &_self->client_arr[client], payload);
}

core_receiver_t output_dnssim_receiver()
{
    return (core_receiver_t)_receive;
}

void output_dnssim_set_transport(output_dnssim_t* self, output_dnssim_transport_t tr) {
    mlassert_self();

    switch(tr) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY:
        lnotice("transport set to UDP (no TCP fallback)");
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
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

void output_dnssim_timeout_ms(output_dnssim_t* self, uint64_t timeout_ms)
{
    mlassert_self();
    lassert(timeout_ms > 0, "timeout must be greater than 0");

    if (self->stats_sum != NULL)
        free(self->stats_sum);
    if (self->stats_current != NULL)
        free(self->stats_current);

    self->timeout_ms = timeout_ms;

    lfatal_oom(self->stats_sum = calloc(1, sizeof(output_dnssim_stats_t)));
    lfatal_oom(self->stats_sum->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    lfatal_oom(self->stats_current = calloc(1, sizeof(output_dnssim_stats_t)));
    lfatal_oom(self->stats_current->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    self->stats_first = self->stats_current;
}

static void _stats_timer_cb(uv_timer_t* handle)
{
    uint64_t now_ms = _now_ms();
    output_dnssim_t* self = (output_dnssim_t*)handle->data;
    lnotice("total processed:%10ld; answers:%10ld; discarded:%10ld; ongoing:%10ld",
        self->processed, self->stats_sum->answers, self->discarded,
        self->ongoing);

    output_dnssim_stats_t* stats_next;
    lfatal_oom(stats_next = calloc(1, sizeof(output_dnssim_stats_t)));
    lfatal_oom(stats_next->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    self->stats_current->until_ms = now_ms;
    stats_next->since_ms = now_ms;
    stats_next->conn_active = self->stats_current->conn_active;

    stats_next->ongoing = self->ongoing;
    stats_next->prev = self->stats_current;
    self->stats_current->next = stats_next;
    self->stats_current = stats_next;
}

void output_dnssim_stats_collect(output_dnssim_t* self, uint64_t interval_ms)
{
    uint64_t now_ms = _now_ms();
    mlassert_self();

    if (self->stats_interval_ms != 0) {
        lfatal("statistics collection has already started!");
    }
    self->stats_interval_ms = interval_ms;

    self->stats_sum->since_ms = now_ms;
    self->stats_current->since_ms = now_ms;

    _self->stats_timer.data = (void*)self;
    uv_timer_init(&_self->loop, &_self->stats_timer);
    uv_timer_start(&_self->stats_timer, _stats_timer_cb, interval_ms, interval_ms);
}

void output_dnssim_stats_finish(output_dnssim_t* self)
{
    uint64_t now_ms = _now_ms();
    mlassert_self();

    self->stats_sum->until_ms = now_ms;
    self->stats_current->until_ms = now_ms;

    uv_timer_stop(&_self->stats_timer);
    uv_close((uv_handle_t*)&_self->stats_timer, NULL);
}

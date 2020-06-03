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

#include <string.h>

static core_log_t _log = LOG_T_INIT("output.dnssim");

static void _close_request(_output_dnssim_request_t* req);

static void _on_request_timeout(uv_timer_t* handle)
{
    _close_request((_output_dnssim_request_t*)handle->data);
}

void _output_dnssim_create_request(output_dnssim_t* self, _output_dnssim_client_t* client, core_object_payload_t* payload)
{
    int                       ret;
    _output_dnssim_request_t* req;
    mlassert_self();
    lassert(client, "client is nil");
    lassert(payload, "payload is nil");

    lfatal_oom(req = calloc(1, sizeof(_output_dnssim_request_t)));
    req->dnssim          = self;
    req->client          = client;
    req->payload         = payload;
    req->dns_q           = core_object_dns_new();
    req->dns_q->obj_prev = (core_object_t*)req->payload;
    req->dnssim->ongoing++;
    req->state = _OUTPUT_DNSSIM_REQ_ONGOING;
    req->stats = self->stats_current;

    ret = core_object_dns_parse_header(req->dns_q);
    if (ret != 0) {
        ldebug("discarded malformed dns query: couldn't parse header");
        goto failure;
    }

    req->dnssim->stats_sum->requests++;
    req->stats->requests++;

    switch (_self->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY:
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
        ret = _output_dnssim_create_query_udp(self, req);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        ret = _output_dnssim_create_query_tcp(self, req);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
        ret = _output_dnssim_create_query_tls(self, req);
#else
        lfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        break;
    default:
        lfatal("unsupported dnssim transport");
        break;
    }
    if (ret < 0) {
        goto failure;
    }

    req->created_at = uv_now(&_self->loop);
    req->ended_at   = req->created_at + self->timeout_ms;
    lfatal_oom(req->timer = malloc(sizeof(uv_timer_t)));
    uv_timer_init(&_self->loop, req->timer);
    req->timer->data = req;
    uv_timer_start(req->timer, _on_request_timeout, self->timeout_ms, 0);

    return;
failure:
    self->discarded++;
    _close_request(req);
    return;
}

/* Bind before connect to be able to send from different source IPs. */
int _output_dnssim_bind_before_connect(output_dnssim_t* self, uv_handle_t* handle)
{
    mlassert_self();
    lassert(handle, "handle is nil");

    if (_self->source != NULL) {
        struct sockaddr* addr = (struct sockaddr*)&_self->source->addr;
        int              ret  = -1;
        switch (handle->type) {
        case UV_UDP:
            ret = uv_udp_bind((uv_udp_t*)handle, addr, 0);
            break;
        case UV_TCP:
            ret = uv_tcp_bind((uv_tcp_t*)handle, addr, 0);
            break;
        default:
            lfatal("bind before connect: unsupported handle type");
            break;
        }
        if (ret < 0) {
            lwarning("failed to bind to address: %s", uv_strerror(ret));
            return ret;
        }
        _self->source = _self->source->next;
    }
    return 0;
}

void _output_dnssim_maybe_free_request(_output_dnssim_request_t* req)
{
    mlassert(req, "req is nil");

    if (req->qry == NULL && req->timer == NULL) {
        if (req->dnssim->free_after_use) {
            core_object_payload_free(req->payload);
        }
        core_object_dns_free(req->dns_q);
        free(req);
    }
}

static void _close_query(_output_dnssim_query_t* qry)
{
    mlassert(qry, "qry is nil");

    switch (qry->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
        _output_dnssim_close_query_udp((_output_dnssim_query_udp_t*)qry);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        _output_dnssim_close_query_tcp((_output_dnssim_query_tcp_t*)qry);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
        _output_dnssim_close_query_tls((_output_dnssim_query_tcp_t*)qry);
#else
        mlfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        break;
    default:
        mlfatal("invalid query transport");
        break;
    }
}

static void _on_request_timer_closed(uv_handle_t* handle)
{
    _output_dnssim_request_t* req = (_output_dnssim_request_t*)handle->data;
    mlassert(req, "req is nil");
    free(handle);
    req->timer = NULL;
    _output_dnssim_maybe_free_request(req);
}

static void _close_request(_output_dnssim_request_t* req)
{
    if (req == NULL || req->state == _OUTPUT_DNSSIM_REQ_CLOSING)
        return;
    mlassert(req->state == _OUTPUT_DNSSIM_REQ_ONGOING, "request to be closed must be ongoing");
    req->state = _OUTPUT_DNSSIM_REQ_CLOSING;
    req->dnssim->ongoing--;

    /* Calculate latency. */
    uint64_t latency;
    req->ended_at = uv_now(&((_output_dnssim_t*)req->dnssim)->loop);
    latency       = req->ended_at - req->created_at;
    if (latency > req->dnssim->timeout_ms) {
        req->ended_at = req->created_at + req->dnssim->timeout_ms;
        latency       = req->dnssim->timeout_ms;
    }
    req->stats->latency[latency]++;
    req->dnssim->stats_sum->latency[latency]++;

    if (req->timer != NULL) {
        uv_timer_stop(req->timer);
        uv_close((uv_handle_t*)req->timer, _on_request_timer_closed);
    }

    /* Finish any queries in flight. */
    _output_dnssim_query_t* qry = req->qry;
    if (qry != NULL)
        _close_query(qry);

    _output_dnssim_maybe_free_request(req);
}

void _output_dnssim_request_answered(_output_dnssim_request_t* req, core_object_dns_t* msg)
{
    mlassert(req, "req is nil");
    mlassert(msg, "msg is nil");

    req->dnssim->stats_sum->answers++;
    req->stats->answers++;

    switch (msg->rcode) {
    case CORE_OBJECT_DNS_RCODE_NOERROR:
        req->dnssim->stats_sum->rcode_noerror++;
        req->stats->rcode_noerror++;
        break;
    case CORE_OBJECT_DNS_RCODE_FORMERR:
        req->dnssim->stats_sum->rcode_formerr++;
        req->stats->rcode_formerr++;
        break;
    case CORE_OBJECT_DNS_RCODE_SERVFAIL:
        req->dnssim->stats_sum->rcode_servfail++;
        req->stats->rcode_servfail++;
        break;
    case CORE_OBJECT_DNS_RCODE_NXDOMAIN:
        req->dnssim->stats_sum->rcode_nxdomain++;
        req->stats->rcode_nxdomain++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTIMP:
        req->dnssim->stats_sum->rcode_notimp++;
        req->stats->rcode_notimp++;
        break;
    case CORE_OBJECT_DNS_RCODE_REFUSED:
        req->dnssim->stats_sum->rcode_refused++;
        req->stats->rcode_refused++;
        break;
    case CORE_OBJECT_DNS_RCODE_YXDOMAIN:
        req->dnssim->stats_sum->rcode_yxdomain++;
        req->stats->rcode_yxdomain++;
        break;
    case CORE_OBJECT_DNS_RCODE_YXRRSET:
        req->dnssim->stats_sum->rcode_yxrrset++;
        req->stats->rcode_yxrrset++;
        break;
    case CORE_OBJECT_DNS_RCODE_NXRRSET:
        req->dnssim->stats_sum->rcode_nxrrset++;
        req->stats->rcode_nxrrset++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTAUTH:
        req->dnssim->stats_sum->rcode_notauth++;
        req->stats->rcode_notauth++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTZONE:
        req->dnssim->stats_sum->rcode_notzone++;
        req->stats->rcode_notzone++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADVERS:
        req->dnssim->stats_sum->rcode_badvers++;
        req->stats->rcode_badvers++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADKEY:
        req->dnssim->stats_sum->rcode_badkey++;
        req->stats->rcode_badkey++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADTIME:
        req->dnssim->stats_sum->rcode_badtime++;
        req->stats->rcode_badtime++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADMODE:
        req->dnssim->stats_sum->rcode_badmode++;
        req->stats->rcode_badmode++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADNAME:
        req->dnssim->stats_sum->rcode_badname++;
        req->stats->rcode_badname++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADALG:
        req->dnssim->stats_sum->rcode_badalg++;
        req->stats->rcode_badalg++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADTRUNC:
        req->dnssim->stats_sum->rcode_badtrunc++;
        req->stats->rcode_badtrunc++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADCOOKIE:
        req->dnssim->stats_sum->rcode_badcookie++;
        req->stats->rcode_badcookie++;
        break;
    default:
        req->dnssim->stats_sum->rcode_other++;
        req->stats->rcode_other++;
    }

    _close_request(req);
}

void _output_dnssim_on_uv_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    mlfatal_oom(buf->base = malloc(suggested_size));
    buf->len = suggested_size;
}

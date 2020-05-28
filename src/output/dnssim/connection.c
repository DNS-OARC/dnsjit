/*
 * Copyright (c) 2020, CZ.NIC, z.s.p.o.
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

static bool _conn_is_connecting(_output_dnssim_connection_t* conn)
{
    return (conn->state >= _OUTPUT_DNSSIM_CONN_TCP_HANDSHAKE && conn->state <= _OUTPUT_DNSSIM_CONN_ACTIVE);
}

void _output_dnssim_conn_maybe_free(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->client, "conn must belong to a client");
    if (conn->handle == NULL && conn->handshake_timer == NULL && conn->idle_timer == NULL) {
        _ll_remove(conn->client->conn, conn);
        if (conn->tls != NULL) {
            free(conn->tls);
            conn->tls = NULL;
        }
        free(conn);
    }
}

static void _on_handshake_timer_closed(uv_handle_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    mlassert(conn, "conn is nil");
    mlassert(conn->handshake_timer, "conn must have handshake timer when closing it");
    free(conn->handshake_timer);
    conn->handshake_timer = NULL;
    _output_dnssim_conn_maybe_free(conn);
}

static void _on_idle_timer_closed(uv_handle_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    mlassert(conn, "conn is nil");
    mlassert(conn->idle_timer, "conn must have idle timer when closing it");
    free(conn->idle_timer);
    conn->is_idle    = false;
    conn->idle_timer = NULL;
    _output_dnssim_conn_maybe_free(conn);
}

void _output_dnssim_conn_close(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->stats, "conn must have stats");
    mlassert(conn->client, "conn must have client");
    mlassert(conn->client->dnssim, "client must have dnssim");

    output_dnssim_t* self = conn->client->dnssim;

    switch (conn->state) {
    case _OUTPUT_DNSSIM_CONN_CLOSING:
    case _OUTPUT_DNSSIM_CONN_CLOSED:
        return;
    case _OUTPUT_DNSSIM_CONN_TCP_HANDSHAKE:
    case _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE:
        conn->stats->conn_handshakes_failed++;
        self->stats_sum->conn_handshakes_failed++;
        break;
    case _OUTPUT_DNSSIM_CONN_ACTIVE:
        self->stats_current->conn_active--;
        break;
    default:
        break;
    }
    conn->state = _OUTPUT_DNSSIM_CONN_CLOSING;

    if (conn->handshake_timer != NULL) {
        uv_timer_stop(conn->handshake_timer);
        uv_close((uv_handle_t*)conn->handshake_timer, _on_handshake_timer_closed);
    }
    if (conn->idle_timer != NULL) {
        conn->is_idle = false;
        uv_timer_stop(conn->idle_timer);
        uv_close((uv_handle_t*)conn->idle_timer, _on_idle_timer_closed);
    }

    switch(_self->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        _output_dnssim_tcp_close(conn);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
        _output_dnssim_tls_close(conn);
        break;
    default:
        lfatal("unsupported transport");
        break;
    }

}

/* Close connection or run idle timer when there are no more outstanding queries. */
void _output_dnssim_conn_idle(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");

    if (conn->queued == NULL && conn->sent == NULL) {
        if (conn->idle_timer == NULL)
            _output_dnssim_conn_close(conn);
        else if (!conn->is_idle) {
            conn->is_idle = true;
            uv_timer_again(conn->idle_timer);
        }
    }
}

static void _send_pending_queries(_output_dnssim_connection_t* conn)
{
    _output_dnssim_query_tcp_t* qry;
    mlassert(conn, "conn is nil");
    mlassert(conn->client, "conn->client is nil");
    qry = (_output_dnssim_query_tcp_t*)conn->client->pending;

    while (qry != NULL && conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE) {
        _output_dnssim_query_tcp_t* next = (_output_dnssim_query_tcp_t*)qry->qry.next;
        if (qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE) {
            switch(qry->qry.transport) {
            case OUTPUT_DNSSIM_TRANSPORT_TCP:
                _output_dnssim_tcp_write_query(conn, qry);
                break;
            case OUTPUT_DNSSIM_TRANSPORT_TLS:
                _output_dnssim_tls_write_query(conn, qry);
                break;
            default:
                mlfatal("unsupported protocol");
                break;
            }
        }
        qry = next;
    }
}

int _output_dnssim_handle_pending_queries(_output_dnssim_client_t* client)
{
    int ret = 0;
    mlassert(client, "client is nil");

    if (client->pending == NULL)
        return ret;

    output_dnssim_t* self = client->dnssim;
    mlassert(self, "client must belong to dnssim");

    /* Get active connection or find out whether new connection has to be opened. */
    bool                         is_connecting = false;
    _output_dnssim_connection_t* conn          = client->conn;
    while (conn != NULL) {
        if (conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE)
            break;
        else if (_conn_is_connecting(conn))
            is_connecting = true;
        conn              = conn->next;
    }

    if (conn != NULL) { /* Send data right away over active connection. */
        _send_pending_queries(conn);
    } else if (!is_connecting) { /* No active or connecting connection -> open a new one. */
        lfatal_oom(conn = calloc(1, sizeof(_output_dnssim_connection_t)));
        conn->state  = _OUTPUT_DNSSIM_CONN_INITIALIZED;
        conn->client = client;
        conn->stats  = self->stats_current;
        if (_self->transport == OUTPUT_DNSSIM_TRANSPORT_TLS) {
            ret = _output_dnssim_tls_init(conn);
            if (ret < 0)
                return ret;
        }
        ret = _output_dnssim_tcp_connect(self, conn);
        if (ret < 0)
            return ret;
        _ll_append(client->conn, conn);
    } /* Otherwise, pending queries wil be sent after connected callback. */

    return ret;
}

void _output_dnssim_conn_activate(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->client, "conn must be associated with a client");
    mlassert(conn->client->dnssim, "client must be associated with dnssim");

    uv_timer_stop(conn->handshake_timer);

    conn->state = _OUTPUT_DNSSIM_CONN_ACTIVE;
    conn->client->dnssim->stats_current->conn_active++;
    conn->read_state          = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
    conn->dnsbuf_len            = 2;
    conn->dnsbuf_pos            = 0;
    conn->dnsbuf_free_after_use = false;

    _send_pending_queries(conn);
    _output_dnssim_conn_idle(conn);
}

int _process_dnsmsg(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");

    core_object_payload_t payload = CORE_OBJECT_PAYLOAD_INIT(NULL);
    core_object_dns_t     dns_a   = CORE_OBJECT_DNS_INIT(&payload);

    payload.payload = (uint8_t*)conn->dnsbuf_data;
    payload.len     = conn->dnsbuf_len;

    dns_a.obj_prev = (core_object_t*)&payload;
    int ret        = core_object_dns_parse_header(&dns_a);
    if (ret != 0) {
        mlwarning("tcp response malformed");
        return _ERR_MALFORMED;
    }
    mldebug("tcp recv dnsmsg id: %04x", dns_a.id);

    _output_dnssim_query_t* qry = conn->sent;
    while (qry != NULL) {
        if (qry->req->dns_q->id == dns_a.id) {
            /* NOTE: QNAME, QTYPE and QCLASS checking (RFC 7766, Section 7) is
             * omitted, since the MSGID is unique per connection. */
            _output_dnssim_request_answered(qry->req, &dns_a);
            break;
        }
        qry = qry->next;
    }

    return 0;
}

static int _parse_dnsbuf_data(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->dnsbuf_pos == conn->dnsbuf_len, "attempt to parse incomplete dnsbuf_data");
    int ret = 0;

    switch (conn->read_state) {
    case _OUTPUT_DNSSIM_READ_STATE_DNSLEN: {
        uint16_t* p_dnslen = (uint16_t*)conn->dnsbuf_data;
        conn->dnsbuf_len     = ntohs(*p_dnslen);
        if (conn->dnsbuf_len == 0) {
            mlwarning("invalid dnslen received: 0");
            conn->dnsbuf_len = 2;
            conn->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
        } else if (conn->dnsbuf_len < 12) {
            mldebug("invalid dnslen received: %d", conn->dnsbuf_len);
            ret = -1;
        } else {
            mldebug("dnslen: %d", conn->dnsbuf_len);
            conn->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSMSG;
        }
        break;
    }
    case _OUTPUT_DNSSIM_READ_STATE_DNSMSG:
        ret = _process_dnsmsg(conn);
        if (ret) {
            conn->read_state = _OUTPUT_DNSSIM_READ_STATE_INVALID;
        } else {
            conn->dnsbuf_len   = 2;
            conn->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
        }
        break;
    default:
        mlfatal("tcp invalid connection read_state");
        break;
    }

    conn->dnsbuf_pos = 0;
    if (conn->dnsbuf_free_after_use) {
        conn->dnsbuf_free_after_use = false;
        free(conn->dnsbuf_data);
    }
    conn->dnsbuf_data = NULL;

    return ret;
}

static unsigned int _read_dns_stream_chunk(_output_dnssim_connection_t* conn, size_t len, const char* data)
{
    mlassert(conn, "conn can't be nil");
    mlassert(data, "data can't be nil");
    mlassert(len > 0, "no data to read");
    mlassert((conn->read_state == _OUTPUT_DNSSIM_READ_STATE_DNSLEN || conn->read_state == _OUTPUT_DNSSIM_READ_STATE_DNSMSG),
            "connection has invalid read_state");

    int          ret = 0;
    unsigned int nread;
    size_t       expected = conn->dnsbuf_len - conn->dnsbuf_pos;
    mlassert(expected > 0, "no data expected");

    if (conn->dnsbuf_free_after_use == false && expected > len) {
        /* Start of partial read. */
        mlassert(conn->dnsbuf_pos == 0, "conn->dnsbuf_pos must be 0 at start of partial read");
        mlassert(conn->dnsbuf_len > 0, "conn->dnsbuf_len must be set at start of partial read");
        mlfatal_oom(conn->dnsbuf_data = malloc(conn->dnsbuf_len * sizeof(char)));
        conn->dnsbuf_free_after_use = true;
    }

    if (conn->dnsbuf_free_after_use) { /* Partial read is in progress. */
        char* dest = conn->dnsbuf_data + conn->dnsbuf_pos;
        if (expected < len)
            len = expected;
        memcpy(dest, data, len);
        conn->dnsbuf_pos += len;
        nread = len;
    } else { /* Complete and clean read. */
        mlassert(expected <= len, "not enough data to perform complete read");
        conn->dnsbuf_data = (char*)data;
        conn->dnsbuf_pos  = conn->dnsbuf_len;
        nread           = expected;
    }

    /* If entire dnslen/dnsmsg was read, attempt to parse it. */
    if (conn->dnsbuf_len == conn->dnsbuf_pos) {
        ret = _parse_dnsbuf_data(conn);
        if (ret < 0)
            return ret;
    }

    return nread;
}

void _output_dnssim_read_dns_stream(_output_dnssim_connection_t* conn, size_t len, const char* data)
{
    int   pos   = 0;
    int   chunk = 0;
    while (pos < len) {
        chunk = _read_dns_stream_chunk(conn, len - pos, data + pos);
        if (chunk < 0) {
            mlwarning("lost orientation in DNS stream, closing");
            _output_dnssim_conn_close(conn);
            break;
        } else {
            pos += chunk;
        }
    }
    mlassert((pos == len) || (chunk < 0), "dns stream read invalid, pos != len");
}

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
    return (conn->state == _OUTPUT_DNSSIM_CONN_TCP_HANDSHAKE);
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
        lfatal("TODO: implement tls conn close");
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

    // TODO support TLS
    while (qry != NULL) {
        _output_dnssim_query_tcp_t* next = (_output_dnssim_query_tcp_t*)qry->qry.next;
        if (qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE)
            _output_dnssim_tcp_write_query(conn, qry);
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

    /* Get active TCP connection or find out whether new connection has to be opened. */
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
        ret          = _output_dnssim_tcp_connect(self, conn);  // TODO tls
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

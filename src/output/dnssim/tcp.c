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

static void _move_queries_to_pending(_output_dnssim_query_tcp_t* qry)
{
    _output_dnssim_query_tcp_t* qry_tmp;
    while (qry != NULL) {
        mlassert(qry->conn, "query must be associated with conn");
        mlassert(qry->conn->state == _OUTPUT_DNSSIM_CONN_CLOSED, "conn must be closed");
        mlassert(qry->conn->client, "conn must be associated with client");
        qry_tmp       = (_output_dnssim_query_tcp_t*)qry->qry.next;
        qry->qry.next = NULL;
        _ll_append(qry->conn->client->pending, &qry->qry);
        qry->conn         = NULL;
        qry->qry.state    = _OUTPUT_DNSSIM_QUERY_ORPHANED;
        qry->stream_id    = -1;
        qry->recv_buf_len = 0;
        if (qry->recv_buf != NULL) {
            free(qry->recv_buf);
            qry->recv_buf = NULL;
        }
        qry = qry_tmp;
    }
}

static void _on_tcp_closed(uv_handle_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    mlassert(conn, "conn is nil");
    conn->state = _OUTPUT_DNSSIM_CONN_CLOSED;

    /* Orphan any queries that are still unresolved. */
    _move_queries_to_pending((_output_dnssim_query_tcp_t*)conn->queued);
    conn->queued = NULL;
    _move_queries_to_pending((_output_dnssim_query_tcp_t*)conn->sent);
    conn->sent = NULL;

    /* TODO Improve client re-connect behavior in case the connection fails to
     * establish. Currently, queries are orphaned and attempted to be re-sent
     * along with the next query that triggers a new connection.
     *
     * Attempting to establish new connection immediately leads to performance
     * issues if the number of these attempts doesn't have upper limit. */
    ///* Ensure orhpaned queries are re-sent over a different connection. */
    //if (_output_dnssim_handle_pending_queries(conn->client) != 0)
    //    mlinfo("tcp: orphaned queries failed to be re-sent");

    mlassert(conn->handle, "conn must have tcp handle when closing it");
    free(conn->handle);
    conn->handle = NULL;
    _output_dnssim_conn_maybe_free(conn);
}

static void _on_tcp_query_written(uv_write_t* wr_req, int status)
{
    _output_dnssim_query_tcp_t* qry = (_output_dnssim_query_tcp_t*)wr_req->data;
    mlassert(qry, "qry/wr_req->data is nil");
    mlassert(qry->conn, "query must be associated with connection");
    _output_dnssim_connection_t* conn = qry->conn;

    free(((_output_dnssim_query_tcp_t*)qry)->bufs[0].base);

    if (qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_CLOSE) {
        qry->qry.state                = status < 0 ? _OUTPUT_DNSSIM_QUERY_WRITE_FAILED : _OUTPUT_DNSSIM_QUERY_SENT;
        _output_dnssim_request_t* req = qry->qry.req;
        _output_dnssim_close_query_tcp(qry);
        _output_dnssim_maybe_free_request(req);
        qry = NULL;
    }

    if (status < 0) {
        if (status != UV_ECANCELED)
            mlinfo("tcp write failed: %s", uv_strerror(status));
        if (qry != NULL)
            qry->qry.state = _OUTPUT_DNSSIM_QUERY_WRITE_FAILED;
        _output_dnssim_conn_close(conn);
        return;
    }

    if (qry == NULL)
        return;

    /* Mark query as sent and assign it to connection. */
    mlassert(qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB, "invalid query state");
    qry->qry.state = _OUTPUT_DNSSIM_QUERY_SENT;
    if (qry->conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE) {
        mlassert(qry->conn->queued, "conn has no queued queries");
        _ll_remove(qry->conn->queued, &qry->qry);
        _ll_append(qry->conn->sent, &qry->qry);
    }
}

void _output_dnssim_tcp_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_tcp_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE, "qry must be pending write");
    mlassert(qry->qry.req, "req can't be null");
    mlassert(qry->qry.req->dns_q, "dns_q can't be null");
    mlassert(qry->qry.req->dns_q->obj_prev, "payload can't be null");
    mlassert(conn, "conn can't be null");
    mlassert(conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE, "connection state != ACTIVE");
    mlassert(conn->client, "conn must be associated with client");
    mlassert(conn->client->pending, "conn has no pending queries");

    mldebug("tcp write dnsmsg id: %04x", qry->qry.req->dns_q->id);

    core_object_payload_t* payload = (core_object_payload_t*)qry->qry.req->dns_q->obj_prev;
    uint16_t*              len;
    mlfatal_oom(len = malloc(sizeof(uint16_t)));
    *len         = htons(payload->len);
    qry->bufs[0] = uv_buf_init((char*)len, 2);
    qry->bufs[1] = uv_buf_init((char*)payload->payload, payload->len);

    qry->conn = conn;
    _ll_remove(conn->client->pending, &qry->qry);
    _ll_append(conn->queued, &qry->qry);

    /* Stop idle timer, since there are queries to answer now. */
    if (conn->idle_timer != NULL) {
        conn->is_idle = false;
        uv_timer_stop(conn->idle_timer);
    }

    qry->write_req.data = (void*)qry;
    uv_write(&qry->write_req, (uv_stream_t*)conn->handle, qry->bufs, 2, _on_tcp_query_written);
    qry->qry.state = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB;
}

static void _on_tcp_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    output_dnssim_t*             self = conn->client->dnssim;

    if (nread > 0) {
        mldebug("tcp nread: %d", nread);
        switch (_self->transport) {
        case OUTPUT_DNSSIM_TRANSPORT_TCP:
            _output_dnssim_read_dns_stream(conn, nread, buf->base);
            break;
        case OUTPUT_DNSSIM_TRANSPORT_TLS:
        case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
            mlassert(conn->tls, "con must have tls ctx");
            conn->tls->buf     = (uint8_t*)buf->base;
            conn->tls->buf_pos = 0;
            conn->tls->buf_len = nread;
            _output_dnssim_tls_process_input_data(conn);
#else
            mlfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
            break;
        default:
            mlfatal("unsupported transport");
            break;
        }
    } else if (nread < 0) {
        if (nread != UV_EOF)
            mlinfo("tcp conn unexpected close: %s", uv_strerror(nread));
        _output_dnssim_conn_close(conn);
    }

    if (buf->base != NULL)
        free(buf->base);
}

static void _on_tcp_connected(uv_connect_t* conn_req, int status)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)conn_req->handle->data;
    mlassert(conn, "conn is nil");

    free(conn_req);

    if (status < 0) {
        mldebug("tcp connect failed: %s", uv_strerror(status));
        _output_dnssim_conn_close(conn);
        return;
    }

    mlassert(conn->state == _OUTPUT_DNSSIM_CONN_TCP_HANDSHAKE, "connection state != TCP_HANDSHAKE");
    int ret = uv_read_start((uv_stream_t*)conn->handle, _output_dnssim_on_uv_alloc, _on_tcp_read);
    if (ret < 0) {
        mlwarning("tcp uv_read_start() failed: %s", uv_strerror(ret));
        _output_dnssim_conn_close(conn);
        return;
    }

    mldebug("tcp connected");
    mlassert(conn->client, "conn must be associated with a client");
    mlassert(conn->client->dnssim, "client must be associated with dnssim");
    output_dnssim_t* self = conn->client->dnssim;
    switch (_self->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        _output_dnssim_conn_activate(conn);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
    case OUTPUT_DNSSIM_TRANSPORT_HTTPS2:
#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION
        mldebug("init tls handshake");
        _output_dnssim_tls_process_input_data(conn); /* Initiate TLS handshake. */
#else
        mlfatal(DNSSIM_MIN_GNUTLS_ERRORMSG);
#endif
        break;
    default:
        lfatal("unsupported transport protocol");
        break;
    }
}

static void _on_connection_timeout(uv_timer_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    _output_dnssim_conn_close(conn);
}

int _output_dnssim_tcp_connect(output_dnssim_t* self, _output_dnssim_connection_t* conn)
{
    mlassert_self();
    lassert(conn, "connection can't be null");
    lassert(conn->handle == NULL, "connection already has a handle");
    lassert(conn->handshake_timer == NULL, "connection already has a handshake timer");
    lassert(conn->idle_timer == NULL, "connection already has idle timer");
    lassert(conn->state == _OUTPUT_DNSSIM_CONN_INITIALIZED, "connection state != INITIALIZED");

    lfatal_oom(conn->handle = malloc(sizeof(uv_tcp_t)));
    conn->handle->data = (void*)conn;
    int ret            = uv_tcp_init(&_self->loop, conn->handle);
    if (ret < 0) {
        lwarning("failed to init uv_tcp_t");
        goto failure;
    }

    ret = _output_dnssim_bind_before_connect(self, (uv_handle_t*)conn->handle);
    if (ret < 0)
        goto failure;

    /* Set connection parameters. */
    ret = uv_tcp_nodelay(conn->handle, 1);
    if (ret < 0)
        lwarning("tcp: failed to set TCP_NODELAY: %s", uv_strerror(ret));

    /* Set connection handshake timeout. */
    lfatal_oom(conn->handshake_timer = malloc(sizeof(uv_timer_t)));
    uv_timer_init(&_self->loop, conn->handshake_timer);
    conn->handshake_timer->data = (void*)conn;
    uv_timer_start(conn->handshake_timer, _on_connection_timeout, self->handshake_timeout_ms, 0);

    /* Set idle connection timer. */
    if (self->idle_timeout_ms > 0) {
        lfatal_oom(conn->idle_timer = malloc(sizeof(uv_timer_t)));
        uv_timer_init(&_self->loop, conn->idle_timer);
        conn->idle_timer->data = (void*)conn;

        /* Start and stop the timer to set the repeat value without running the timer. */
        uv_timer_start(conn->idle_timer, _on_connection_timeout, self->idle_timeout_ms, self->idle_timeout_ms);
        uv_timer_stop(conn->idle_timer);
    }

    mldebug("tcp connecting");
    uv_connect_t* conn_req;
    lfatal_oom(conn_req = malloc(sizeof(uv_connect_t)));
    ret = uv_tcp_connect(conn_req, conn->handle, (struct sockaddr*)&_self->target, _on_tcp_connected);
    if (ret < 0)
        goto failure;

    conn->stats->conn_handshakes++;
    conn->client->dnssim->stats_sum->conn_handshakes++;
    conn->state = _OUTPUT_DNSSIM_CONN_TCP_HANDSHAKE;
    return 0;
failure:
    _output_dnssim_conn_close(conn);
    return ret;
}

void _output_dnssim_tcp_close(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");

    if (conn->handle != NULL) {
        uv_read_stop((uv_stream_t*)conn->handle);
        uv_close((uv_handle_t*)conn->handle, _on_tcp_closed);
    }
}

int _output_dnssim_create_query_tcp(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();
    lassert(req, "req is nil");
    lassert(req->client, "request must have a client associated with it");

    _output_dnssim_query_tcp_t* qry;

    lfatal_oom(qry = calloc(1, sizeof(_output_dnssim_query_tcp_t)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_TCP;
    qry->qry.req       = req;
    qry->qry.state     = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE;
    req->qry           = &qry->qry; // TODO change when adding support for multiple Qs for req
    _ll_append(req->client->pending, &qry->qry);

    return _output_dnssim_handle_pending_queries(req->client);
}

void _output_dnssim_close_query_tcp(_output_dnssim_query_tcp_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.req, "query must be part of a request");
    _output_dnssim_request_t* req = qry->qry.req;
    mlassert(req->client, "request must belong to a client");

    if ((qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB || qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_CLOSE)) {
        /* Query can't be freed until uv callback is called. */
        qry->qry.state = _OUTPUT_DNSSIM_QUERY_PENDING_CLOSE;
        return;
    }

    _ll_try_remove(req->client->pending, &qry->qry);
    if (qry->conn) {
        _output_dnssim_connection_t* conn = qry->conn;
        _ll_try_remove(conn->queued, &qry->qry); /* edge-case of cancelled queries */
        _ll_try_remove(conn->sent, &qry->qry);
        qry->conn = NULL;
        _output_dnssim_conn_idle(conn);
    }

    _ll_remove(req->qry, &qry->qry);
    free(qry);
}

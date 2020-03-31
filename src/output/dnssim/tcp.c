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

static void _maybe_free_connection(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->client, "conn must belong to a client");
    if (conn->handle == NULL && conn->handshake_timer == NULL && conn->idle_timer == NULL) {
        _ll_remove(conn->client->conn, conn);
        free(conn);
    }
}

static void _on_tcp_handle_closed(uv_handle_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    conn->state = _OUTPUT_DNSSIM_CONN_CLOSED;
    mlassert(conn->handle, "conn must have tcp handle when closing it");
    free(conn->handle);
    conn->handle = NULL;
    _maybe_free_connection(conn);
}

static void _on_handshake_timer_closed(uv_handle_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    mlassert(conn->handshake_timer, "conn must have handshake timer when closing it");
    free(conn->handshake_timer);
    conn->handshake_timer = NULL;
    _maybe_free_connection(conn);
}

static void _on_idle_timer_closed(uv_handle_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    mlassert(conn->idle_timer, "conn must have idle timer when closing it");
    free(conn->idle_timer);
    conn->is_idle = false;
    conn->idle_timer = NULL;
    _maybe_free_connection(conn);
}

static void _write_tcp_query_cb(uv_write_t* wr_req, int status)
{
    _output_dnssim_query_tcp_t* qry = (_output_dnssim_query_tcp_t*)wr_req->data;

    if (status < 0) {
        if (status != UV_ECANCELED)
            mlinfo("tcp write failed: %s", uv_strerror(status));
        if (qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB) {
            qry->qry.state = _OUTPUT_DNSSIM_QUERY_WRITE_FAILED;
            mlassert(qry->conn, "query must be associated with connection");
            _close_connection(qry->conn);
        }
    } else if (qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB) {
        /* Mark query as sent and assign it to connection. */
        qry->qry.state = _OUTPUT_DNSSIM_QUERY_SENT;
        mlassert(qry->conn, "query must be associated with connection");
        if (qry->conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE) {
            mlassert(qry->conn->queued, "conn has no queued queries");
            _ll_remove(qry->conn->queued, &qry->qry);
            _ll_append(qry->conn->sent, &qry->qry);
        }
    }

    if (qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_CLOSE) {
        qry->qry.state = _OUTPUT_DNSSIM_QUERY_SENT;
        _output_dnssim_request_t* req = qry->qry.req;
        _close_query_tcp(qry);
        _maybe_free_request(req);
    }

    free(((_output_dnssim_query_tcp_t*)qry)->bufs[0].base);
}

static void _write_tcp_query(_output_dnssim_query_tcp_t* qry, _output_dnssim_connection_t* conn)
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
    uint16_t* len;
    mlfatal_oom(len = malloc(sizeof(uint16_t)));
    *len = htons(payload->len);
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
    uv_write(&qry->write_req, (uv_stream_t*)conn->handle, qry->bufs, 2, _write_tcp_query_cb);
    qry->qry.state = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB;
}

static void _send_pending_queries(_output_dnssim_connection_t* conn)
{
    _output_dnssim_query_tcp_t* qry = (_output_dnssim_query_tcp_t*)conn->client->pending;

    while (qry != NULL) {
        _output_dnssim_query_tcp_t* next = (_output_dnssim_query_tcp_t*)qry->qry.next;
        if (qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE)
            _write_tcp_query(qry, conn);
        qry = next;
    }
}

int _process_tcp_dnsmsg(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");

    core_object_payload_t payload = CORE_OBJECT_PAYLOAD_INIT(NULL);
    core_object_dns_t dns_a = CORE_OBJECT_DNS_INIT(&payload);

    payload.payload = conn->recv_data;
    payload.len = conn->recv_len;

    dns_a.obj_prev = (core_object_t*)&payload;
    int ret = core_object_dns_parse_header(&dns_a);
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
            _request_answered(qry->req, &dns_a);
            break;
        }
        qry = qry->next;
    }

    return 0;
}

int _parse_recv_data(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->recv_pos == conn->recv_len, "attempt to parse incomplete recv_data");
    int ret = 0;

    switch(conn->read_state) {
    case _OUTPUT_DNSSIM_READ_STATE_DNSLEN: {
        uint16_t* p_dnslen = (uint16_t*)conn->recv_data;
        conn->recv_len = ntohs(*p_dnslen);
        mldebug("tcp dnslen: %d", conn->recv_len);
        conn->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSMSG;
        break;
    }
    case _OUTPUT_DNSSIM_READ_STATE_DNSMSG:
        ret = _process_tcp_dnsmsg(conn);
        if (ret) {
            conn->read_state = _OUTPUT_DNSSIM_READ_STATE_INVALID;
        } else {
            conn->recv_len = 2;
            conn->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
        }
        break;
    default:
        mlfatal("tcp invalid connection read_state");
        break;
    }

    conn->recv_pos = 0;
    if (conn->recv_free_after_use) {
        conn->recv_free_after_use = false;
        free(conn->recv_data);
    }
    conn->recv_data = NULL;

    return ret;
}

unsigned int _read_tcp_stream(_output_dnssim_connection_t* conn, size_t len, const char* data)
{
    mlassert(conn, "conn can't be nil");
    mlassert(data, "data can't be nil");
    mlassert(len > 0, "no data to read");
    mlassert((conn->read_state == _OUTPUT_DNSSIM_READ_STATE_DNSLEN ||
              conn->read_state == _OUTPUT_DNSSIM_READ_STATE_DNSMSG),
             "connection has invalid read_state");

    int ret = 0;
    unsigned int nread;
    size_t expected = conn->recv_len - conn->recv_pos;
    mlassert(expected > 0, "no data expected");

    if (conn->recv_free_after_use == false && expected > len) {
        /* Start of partial read. */
        mlassert(conn->recv_pos == 0, "conn->recv_pos must be 0 at start of partial read");
        mlassert(conn->recv_len > 0, "conn->recv_len must be set at start of partial read");
        mlfatal_oom(conn->recv_data = malloc(conn->recv_len * sizeof(char)));
        conn->recv_free_after_use = true;
    }

    if (conn->recv_free_after_use) {  /* Partial read is in progress. */
        char* dest = conn->recv_data + conn->recv_pos;
        if (expected < len)
            len = expected;
        memcpy(dest, data, len);
        conn->recv_pos += len;
        nread = len;
    } else {  /* Complete and clean read. */
        mlassert(expected <= len, "not enough data to perform complete read");
        conn->recv_data = (char*)data;
        conn->recv_pos = conn->recv_len;
        nread = expected;
    }

    /* If entire dnslen/dnsmsg was read, attempt to parse it. */
    if (conn->recv_len == conn->recv_pos) {
        ret = _parse_recv_data(conn);
        if (ret < 0)
            return ret;
    }

    return nread;
}

static void _on_tcp_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    if (nread > 0) {
        int pos = 0;
        int chunk = 0;
        char* data = buf->base;
        while (pos < nread) {
            chunk = _read_tcp_stream(conn, nread - pos, data + pos);
            if (chunk < 0) {
                mlwarning("lost orientation in TCP stream, closing");
                _close_connection(conn);
                break;
            } else {
                pos += chunk;
            }
        }
        mlassert((pos == nread) || (chunk < 0), "tcp data read invalid, pos != nread");
    } else if (nread < 0) {
        if (nread != UV_EOF)
            mlinfo("tcp conn unexpected close: %s", uv_strerror(nread));
        _close_connection(conn);
    }

    if (buf->base != NULL)
        free(buf->base);
}

static void _on_tcp_handle_connected(uv_connect_t* conn_req, int status)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)conn_req->handle->data;
    free(conn_req);
    uv_timer_stop(conn->handshake_timer);

    if (status < 0) {
        // TODO handle this better - add some counter?
        mlwarning("tcp connect failed: %s", uv_strerror(status));
        _close_connection(conn);
        return;
    }

    mlassert(conn->state == _OUTPUT_DNSSIM_CONN_CONNECTING, "connection state != CONNECTING");
    int ret = uv_read_start((uv_stream_t*)conn->handle, _uv_alloc_cb, _on_tcp_read);
    if (ret < 0) {
        mlwarning("tcp uv_read_start() failed: %s", uv_strerror(ret));
        _close_connection(conn);
        return;
    }

    conn->state = _OUTPUT_DNSSIM_CONN_ACTIVE;
    conn->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
    conn->recv_len = 2;
    conn->recv_pos = 0;
    conn->recv_free_after_use = false;

    _send_pending_queries(conn);
    _maybe_close_connection(conn);
}

static void _move_queries_to_pending(_output_dnssim_query_tcp_t* qry)
{
    _output_dnssim_query_tcp_t* qry_tmp;
    while (qry != NULL) {
        mlassert(qry->conn, "query must be associated with conn");
        mlassert(qry->conn->client, "conn must be associated with client");
        qry_tmp = (_output_dnssim_query_tcp_t*)qry->qry.next;
        qry->qry.next = NULL;
        _ll_append(qry->conn->client->pending, &qry->qry);
        qry->conn = NULL;
        qry->qry.state = _OUTPUT_DNSSIM_QUERY_ORPHANED;
        qry = qry_tmp;
    }
}

/* Close connection or run idle timer when there are no more outstanding queries. */
static void _maybe_close_connection(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");

    if (conn->queued == NULL && conn->sent == NULL) {
        if (conn->idle_timer == NULL)
            _close_connection(conn);
        else if (!conn->is_idle) {
            conn->is_idle = true;
            uv_timer_again(conn->idle_timer);
        }
    }
}

static void _close_connection(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    if (conn->state == _OUTPUT_DNSSIM_CONN_CLOSING || conn->state == _OUTPUT_DNSSIM_CONN_CLOSED)
        return;
    conn->state = _OUTPUT_DNSSIM_CONN_CLOSING;

    _move_queries_to_pending((_output_dnssim_query_tcp_t*)conn->queued);
    conn->queued = NULL;
    _move_queries_to_pending((_output_dnssim_query_tcp_t*)conn->sent);
    conn->sent = NULL;

    /* Ensure orhpaned queries are re-sent over a different connection. */
    if (_handle_pending_queries(conn->client) != 0)
        mlinfo("tcp: orphaned queries failed to be re-sent");

    if (conn->handshake_timer != NULL) {
        uv_timer_stop(conn->handshake_timer);
        uv_close((uv_handle_t*)conn->handshake_timer, _on_handshake_timer_closed);
    }
    if (conn->idle_timer != NULL) {
        conn->is_idle = false;
        uv_timer_stop(conn->idle_timer);
        uv_close((uv_handle_t*)conn->idle_timer, _on_idle_timer_closed);
    }
    if (conn->handle != NULL) {
        uv_read_stop((uv_stream_t*)conn->handle);
        uv_close((uv_handle_t*)conn->handle, _on_tcp_handle_closed);
    }
}

static void _on_connection_timeout(uv_timer_t* handle)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    _close_connection(conn);
}

static int _connect_tcp_handle(output_dnssim_t* self, _output_dnssim_connection_t* conn)
{
    mlassert_self();
    lassert(conn, "connection can't be null");
    lassert(conn->handle == NULL, "connection already has a handle");
    lassert(conn->handshake_timer == NULL, "connection already has a handshake timer");
    lassert(conn->idle_timer == NULL, "connection already has idle timer");
    lassert(conn->state == _OUTPUT_DNSSIM_CONN_INITIALIZED, "connection state != INITIALIZED");

    lfatal_oom(conn->handle = malloc(sizeof(uv_tcp_t)));
    conn->handle->data = (void*)conn;
    int ret = uv_tcp_init(&_self->loop, conn->handle);
    if (ret < 0) {
        lwarning("failed to init uv_tcp_t");
        goto failure;
    }

    ret = _bind_before_connect(self, (uv_handle_t*)conn->handle);
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

    uv_connect_t* conn_req;
    lfatal_oom(conn_req = malloc(sizeof(uv_connect_t)));
    ret = uv_tcp_connect(conn_req, conn->handle, (struct sockaddr*)&_self->target, _on_tcp_handle_connected);
    if (ret < 0)
        goto failure;

    conn->state = _OUTPUT_DNSSIM_CONN_CONNECTING;
    return 0;
failure:
    _close_connection(conn);
    return ret;
}

static int _handle_pending_queries(_output_dnssim_client_t* client)
{
    int ret = 0;

    if (client->pending == NULL)
        return ret;

    mlassert(client->pending->req, "qry must have req");
    output_dnssim_t* self = client->pending->req->dnssim;
    mlassert_self();

    /* Get active TCP connection or find out whether new connection has to be opened. */
    bool is_connecting = false;
    _output_dnssim_connection_t *conn = client->conn;
    while (conn != NULL) {
        if (conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE)
            break;
        else if (conn->state == _OUTPUT_DNSSIM_CONN_CONNECTING)
            is_connecting = true;
        conn = conn->next;
    }

    if (conn != NULL) {  /* Send data right away over active connection. */
        _send_pending_queries(conn);
    } else if (!is_connecting) {  /* No active or connecting connection -> open a new one. */
        lfatal_oom(conn = calloc(1, sizeof(_output_dnssim_connection_t)));
        conn->state = _OUTPUT_DNSSIM_CONN_INITIALIZED;
        conn->client = client;
        ret = _connect_tcp_handle(self, conn);
        if (ret < 0)
            return ret;
        _ll_append(client->conn, conn);
    } /* Otherwise, pending queries wil be sent after connected callback. */

    return ret;
}

static int _create_query_tcp(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();
    lassert(req->client, "request must have a client associated with it");

    int ret;
    _output_dnssim_query_tcp_t* qry;
    _output_dnssim_connection_t* conn;
    core_object_payload_t* payload = (core_object_payload_t*)req->dns_q->obj_prev;

    lfatal_oom(qry = calloc(1, sizeof(_output_dnssim_query_tcp_t)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_TCP;
    qry->qry.req = req;
    qry->qry.state = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE;
    req->qry = &qry->qry;  // TODO change when adding support for multiple Qs for req
    _ll_append(req->client->pending, &qry->qry);

    return _handle_pending_queries(req->client);
}

static void _close_query_tcp(_output_dnssim_query_tcp_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.req, "query must be part of a request");
    _output_dnssim_request_t* req = qry->qry.req;
    mlassert(req->client, "request must belong to a client");

    if ((qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB ||
         qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_CLOSE)) {
        /* Query can't be freed until uv callback is called. */
        qry->qry.state = _OUTPUT_DNSSIM_QUERY_PENDING_CLOSE;
        return;
    }

    _ll_try_remove(req->client->pending, &qry->qry);
    if (qry->conn) {
        _output_dnssim_connection_t* conn = qry->conn;
        _ll_try_remove(conn->queued, &qry->qry);  /* edge-case of cancelled queries */
        _ll_try_remove(conn->sent, &qry->qry);
        qry->conn = NULL;
        _maybe_close_connection(conn);
    }

    _ll_remove(req->qry, &qry->qry);
    free(qry);
}

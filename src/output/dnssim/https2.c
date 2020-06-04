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

#include <gnutls/gnutls.h>
#include <string.h>

#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION

/* This limits the number of simultaneous streams the *server* can open towards a client.
 * It should have no effect, since we only care about responses to client requests. */
#define DNSSIM_HTTP2_MAX_CONCURRENT_STREAMS 100

static core_log_t _log = LOG_T_INIT("output.dnssim");

static ssize_t _http2_send(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
    mlfatal("TODO implement");
}

static int _http2_on_header(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    mlfatal("TODO implement");
}

static int _http2_on_data_recv(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    mlfatal("TODO implement");
}

int _output_dnssim_https2_init(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->tls == NULL, "conn already has tls context");
    mlassert(conn->http2 == NULL, "conn already has http2 context");

    int ret = -1;
    nghttp2_session_callbacks *callbacks;

    /* Initialize TLS session. */
    ret = _output_dnssim_tls_init(conn);
    if (ret < 0)
        return ret;

    /* Configure ALPN to negotiate HTTP/2. */
    const gnutls_datum_t protos[] = {
        {(unsigned char *)"h2", 2}
    };
    ret = gnutls_alpn_set_protocols(conn->tls->session, protos, 1, 0);
    if (ret < 0) {
        mldebug("failed to set ALPN protocol: %s", gnutls_strerror(ret));
        return ret;
    }

    mlfatal_oom(conn->http2 = calloc(1, sizeof(_output_dnssim_http2_ctx_t)));  // TODO free

    /* Set up HTTP/2 callbacks and client. */
    ret = nghttp2_session_callbacks_new(&callbacks);
    if (ret < 0)
        return ret;
    nghttp2_session_callbacks_set_send_callback(callbacks, _http2_send);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, _http2_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, _http2_on_data_recv);
    ret = nghttp2_session_client_new(&conn->http2->session, callbacks, conn);
    if (ret < 0)
        return ret;
    nghttp2_session_callbacks_del(callbacks);

    ret = 0;
    return ret;
}

int _output_dnssim_https2_setup(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->tls, "conn must have tls ctx");
    mlassert(conn->tls->session, "conn must have tls session");
    mlassert(conn->http2, "conn must have http2 ctx");
    mlassert(conn->http2->session, "conn must have http2 session");

    int ret = -1;

    /* Check "h2" protocol was negotiated with ALPN. */
    gnutls_datum_t proto;
    ret = gnutls_alpn_get_selected_protocol(conn->tls->session, &proto);
    if (ret < 0) {
        mldebug("failed to get negotiated protocol: %s", gnutls_strerror(ret));
        return ret;
    }
    if (proto.size != 2 || memcmp("h2", proto.data, 2) != 0) {
        mldebug("http2 is not negotiated");
        return ret;
    }

    /* Submit SETTIGNS frame. */
    static const nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, DNSSIM_HTTP2_MAX_CONCURRENT_STREAMS }
    };
    ret = nghttp2_submit_settings(conn->http2->session, NGHTTP2_FLAG_NONE, iv, sizeof(iv)/sizeof(*iv) );
    if (ret < 0) {
        mldebug("failed to submit http2 settings: %s", nghttp2_strerror(ret));
        return ret;
    }

    ret = 0;
    return ret;
}

void _output_dnssim_https2_process_input_data(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->client, "conn must have client");
    mlassert(conn->client->dnssim, "client must have dnssim");
    mlassert(conn->tls, "conn must have tls ctx");

    mlfatal("TODO implement");
}

int _output_dnssim_create_query_https2(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();
    lassert(req, "req is nil");
    lassert(req->client, "request must have a client associated with it");

    _output_dnssim_query_tcp_t* qry;

    lfatal_oom(qry = calloc(1, sizeof(_output_dnssim_query_tcp_t)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_HTTPS2;
    qry->qry.req       = req;
    qry->qry.state     = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE;
    req->qry           = &qry->qry; // TODO change when adding support for multiple Qs for req
    _ll_append(req->client->pending, &qry->qry);

    return _output_dnssim_handle_pending_queries(req->client);
}

void _output_dnssim_close_query_https2(_output_dnssim_query_tcp_t* qry)
{
    // TODO reduce copy-pasta if there's no difference from TLS
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.req, "query must be part of a request");
    _output_dnssim_request_t* req = qry->qry.req;
    mlassert(req->client, "request must belong to a client");

    _ll_try_remove(req->client->pending, &qry->qry);
    if (qry->conn) {
        _output_dnssim_connection_t* conn = qry->conn;
        _ll_try_remove(conn->sent, &qry->qry);
        qry->conn = NULL;
        _output_dnssim_conn_idle(conn);
    }

    _ll_remove(req->qry, &qry->qry);
    free(qry);
}

void _output_dnssim_https2_close(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->tls, "conn must have tls ctx");
    mlassert(conn->client, "conn must belong to a client");

    mlfatal("TODO implement");
}

void _output_dnssim_https2_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_tcp_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE, "qry must be pending write");
    mlassert(qry->qry.req, "req can't be null");
    mlassert(qry->qry.req->dns_q, "dns_q can't be null");
    mlassert(qry->qry.req->dns_q->obj_prev, "payload can't be null");
    mlassert(conn, "conn can't be null");
    mlassert(conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE, "connection state != ACTIVE");
    mlassert(conn->tls, "conn must have tls ctx");
    mlassert(conn->client, "conn must be associated with client");
    mlassert(conn->client->pending, "conn has no pending queries");

    mlfatal("TODO implement");
}

#endif

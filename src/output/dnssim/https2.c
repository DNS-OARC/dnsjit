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
#include "lib/base64url.h"

#include <gnutls/gnutls.h>
#include <string.h>

#if GNUTLS_VERSION_NUMBER >= DNSSIM_MIN_GNUTLS_VERSION

#define OUTPUT_DNSSIM_MAKE_NV(NAME, VALUE, VALUELEN)                           \
  {                                                                            \
    (uint8_t* )NAME, (uint8_t* )VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define OUTPUT_DNSSIM_MAKE_NV2(NAME, VALUE)                                    \
  {                                                                            \
    (uint8_t* )NAME, (uint8_t* )VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define OUTPUT_DNSSIM_HTTP_GET_TEMPLATE "?dns="
#define OUTPUT_DNSSIM_HTTP2_INITIAL_MAX_CONCURRENT_STREAMS 100
#define OUTPUT_DNSSIM_HTTP2_DEFAULT_MAX_CONCURRENT_STREAMS 0xffffffffu

static core_log_t _log = LOG_T_INIT("output.dnssim");

static ssize_t _http2_send(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)user_data;
    mlassert(conn, "conn can't be null");
    mlassert(conn->tls, "conn must have tls ctx");
    mlassert(conn->tls->session, "conn must have tls session");

    mldebug("http2 (%p): sending data, len=%ld", session, length);

    ssize_t len = 0;
    if ((len = gnutls_record_send(conn->tls->session, data, length)) < 0) {
        mlwarning("gnutls_record_send failed: %s", gnutls_strerror(len));
        _output_dnssim_conn_close(conn);
        len = NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return len;
}

static ssize_t _http2_on_data_provider_read(nghttp2_session* session, int32_t stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* user_data)
{
    _output_dnssim_https2_data_provider_t* buffer = source->ptr;
    mlassert(buffer, "no data provider");
    mlassert(buffer->len <= MAX_DNSMSG_SIZE, "invalid dnsmsg size: %zu B", buffer->len);

    ssize_t sent = (length < buffer->len) ? length : buffer->len;
    mlassert(sent >= 0, "negative length of bytes to send");

    memcpy(buf, buffer->buf, sent);
    buffer->buf += sent;
    buffer->len -= sent;
    if (buffer->len == 0)
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    return sent;
}

static _output_dnssim_query_tcp_t* _http2_get_stream_qry(_output_dnssim_connection_t* conn, int32_t stream_id)
{
    mlassert(conn, "conn is nil");
    mlassert(stream_id >= 0, "invalid stream_id");

    _output_dnssim_query_tcp_t* qry = (_output_dnssim_query_tcp_t*)conn->sent;
    while (qry != NULL && qry->stream_id != stream_id) {
        qry = (_output_dnssim_query_tcp_t*)qry->qry.next;
    }

    return qry;
}

static int _http2_on_header(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
        if (namelen == 7 && strncmp((char*)name, ":status", 7) == 0) {
            if (valuelen != 3 || (value[0] != '1' && value[0] != '2')) {
                /* When reponse code isn't 1xx or 2xx, close the query.
                 * This will result in request timeout, which currently seems
                 * slightly better than mocking SERVFAIL for statistics. */
                _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)user_data;
                mlassert(conn, "conn is nil");
                _output_dnssim_query_tcp_t* qry = _http2_get_stream_qry(conn, frame->hd.stream_id);

                if (qry != NULL) {
                    _output_dnssim_close_query_https2(qry);
                    mlinfo("http response %s, closing query", value);
                }
            }
        }
    }
    return 0;
}

static int _http2_on_data_recv(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)user_data;
    mlassert(conn, "conn is nil");

    _output_dnssim_query_tcp_t* qry = _http2_get_stream_qry(conn, stream_id);

    mldebug("http2: data chunk recv, session=%p, len=%d", session, len);

    if (qry) {
        if (qry->recv_buf_len == 0) {
            if (len > MAX_DNSMSG_SIZE) {
                mlwarning("http response exceeded maximum size of dns message");
                return -1;
            }
            mlfatal_oom(qry->recv_buf = malloc(len));
            memcpy(qry->recv_buf, data, len);
            qry->recv_buf_len = len;
        } else {
            size_t total_len = qry->recv_buf_len + len;
            if (total_len > MAX_DNSMSG_SIZE) {
                mlwarning("http response exceeded maximum size of dns message");
                return -1;
            }
            mlfatal_oom(qry->recv_buf = realloc(qry->recv_buf, total_len));
            memcpy(qry->recv_buf + qry->recv_buf_len, data, len);
            qry->recv_buf_len = total_len;
        }
    } else {
        mldebug("no query associated with this stream id, ignoring");
    }

    return 0;
}

static void _http2_check_max_streams(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be null");
    mlassert(conn->http2, "conn must have http2 ctx");

    switch (conn->state) {
    case _OUTPUT_DNSSIM_CONN_ACTIVE:
        if (conn->http2->open_streams >= conn->http2->max_concurrent_streams) {
            mlinfo("http2 (%p): reached maximum number of concurrent streams (%ld)",
                conn->http2->session, conn->http2->max_concurrent_streams);
            conn->state = _OUTPUT_DNSSIM_CONN_CONGESTED;
        }
        break;
    case _OUTPUT_DNSSIM_CONN_CONGESTED:
        if (conn->http2->open_streams < conn->http2->max_concurrent_streams)
            conn->state = _OUTPUT_DNSSIM_CONN_ACTIVE;
        break;
    default:
        break;
    }
}

static int _http2_on_stream_close(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)user_data;
    mlassert(conn, "conn can't be null");
    mlassert(conn->http2, "conn must have http2 ctx");
    mlassert(conn->http2->open_streams > 0, "conn has no open streams");

    conn->http2->open_streams--;
    _http2_check_max_streams(conn);
    return 0;
}

static int _http2_on_frame_recv(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)user_data;
    mlassert(conn, "conn can't be null");
    mlassert(conn->tls, "conn must have tls ctx");
    mlassert(conn->tls->session, "conn must have tls session");
    mlassert(conn->http2, "conn must have http2 ctx");

    switch (frame->hd.type) {
    case NGHTTP2_DATA:
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            mldebug("http2 (%p): final DATA frame recv", session);
            _output_dnssim_query_tcp_t* qry = _http2_get_stream_qry(conn, frame->hd.stream_id);

            if (qry != NULL) {
                conn->http2->current_qry = qry;
                _output_dnssim_read_dnsmsg(conn, qry->recv_buf_len, (char*)qry->recv_buf);
            }
        }
        break;
    case NGHTTP2_SETTINGS:
        if (!conn->http2->remote_settings_received) {
            /* On the first SETTINGS frame, set concurrent streams to unlimited, same as nghttp2. */
            conn->http2->remote_settings_received = true;
            conn->http2->max_concurrent_streams = OUTPUT_DNSSIM_HTTP2_DEFAULT_MAX_CONCURRENT_STREAMS;
            _http2_check_max_streams(conn);
        }
        nghttp2_settings* settings = (nghttp2_settings*)frame;
        for (int i = 0; i < settings->niv; i++) {
            switch (settings->iv[i].settings_id) {
            case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                conn->http2->max_concurrent_streams = settings->iv[i].value;
                _http2_check_max_streams(conn);
                break;
            default:
                break;
            }
        }
        break;
    default:
      break;
    }
    return 0;
}

int _output_dnssim_https2_init(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->tls == NULL, "conn already has tls context");
    mlassert(conn->http2 == NULL, "conn already has http2 context");
    mlassert(conn->client, "conn must be associated with a client");
    mlassert(conn->client->dnssim, "client must have dnssim");

    int ret = -1;
    nghttp2_session_callbacks* callbacks;
    nghttp2_option* option;
    output_dnssim_t* self = conn->client->dnssim;

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
        lwarning("failed to set ALPN protocol: %s", gnutls_strerror(ret));
        return ret;
    }

    lfatal_oom(conn->http2 = calloc(1, sizeof(_output_dnssim_http2_ctx_t)));
    conn->http2->max_concurrent_streams = OUTPUT_DNSSIM_HTTP2_INITIAL_MAX_CONCURRENT_STREAMS;

    /* Set up HTTP/2 callbacks and client. */
    lassert(nghttp2_session_callbacks_new(&callbacks) == 0, "out of memory");
    nghttp2_session_callbacks_set_send_callback(callbacks, _http2_send);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, _http2_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, _http2_on_data_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, _http2_on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, _http2_on_stream_close);

    lassert(nghttp2_option_new(&option) == 0, "out of memory");
    nghttp2_option_set_peer_max_concurrent_streams(option, conn->http2->max_concurrent_streams);

    ret = nghttp2_session_client_new2(&conn->http2->session, callbacks, conn, option);

    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(option);

    if (ret < 0) {
        free(conn->http2);
        conn->http2 = NULL;
    }

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
        mlwarning("http2: failed to get negotiated protocol: %s", gnutls_strerror(ret));
        return ret;
    }
    if (proto.size != 2 || memcmp("h2", proto.data, 2) != 0) {
        mlwarning("http2: protocol is not negotiated");
        return ret;
    }

    /* Submit SETTIGNS frame. */
    static const nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_MAX_FRAME_SIZE, MAX_DNSMSG_SIZE },
        { NGHTTP2_SETTINGS_ENABLE_PUSH, 0 },  /* Only we can initiate streams. */
    };
    ret = nghttp2_submit_settings(conn->http2->session, NGHTTP2_FLAG_NONE, iv, sizeof(iv)/sizeof(*iv) );
    if (ret < 0) {
        mlwarning("http2: failed to submit SETTINGS: %s", nghttp2_strerror(ret));
        return ret;
    }

    ret = 0;
    return ret;
}

void _output_dnssim_https2_process_input_data(_output_dnssim_connection_t* conn, size_t len, const char* data)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->http2, "conn must have http2 ctx");
    mlassert(conn->http2->session, "conn must have http2 session");

    /* Process incoming frames. */
    ssize_t ret = 0;
    ret = nghttp2_session_mem_recv(conn->http2->session, (uint8_t*)data, len);
    if (ret < 0) {
        mlwarning("failed nghttp2_session_mem_recv: %s", nghttp2_strerror(ret));
        _output_dnssim_conn_close(conn);
        return;
    }
    mlassert(ret == len, "nghttp2_session_mem_recv didn't process all data");

    /* Send any frames the read might have triggered. */
    ret = nghttp2_session_send(conn->http2->session);
    if (ret < 0) {
        mlwarning("failed nghttp2_session_send: %s", nghttp2_strerror(ret));
        _output_dnssim_conn_close(conn);
        return;
    }
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
    qry->stream_id     = -1;
    req->qry           = &qry->qry; // TODO change when adding support for multiple Qs for req
    _ll_append(req->client->pending, &qry->qry);

    return _output_dnssim_handle_pending_queries(req->client);
}

void _output_dnssim_close_query_https2(_output_dnssim_query_tcp_t* qry)
{
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

    if (qry->recv_buf != NULL)
        free(qry->recv_buf);

    _ll_remove(req->qry, &qry->qry);
    free(qry);
}

void _output_dnssim_https2_close(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->http2, "conn must have http2 ctx");

    nghttp2_session_del(conn->http2->session);
    _output_dnssim_tls_close(conn);
}

static int _http2_send_query_get(_output_dnssim_connection_t* conn, _output_dnssim_query_tcp_t* qry)
{
    mlassert(conn, "conn can't be null");
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.req, "req can't be null");
    mlassert(qry->qry.req->payload, "payload can't be null");
    mlassert(qry->qry.req->payload->len <= MAX_DNSMSG_SIZE, "payload too big");
    mlassert(conn->client, "conn must be associated with client");
    mlassert(conn->client->dnssim, "client must have dnssim");

    output_dnssim_t* self = conn->client->dnssim;
    core_object_payload_t* content = qry->qry.req->payload;

    const size_t path_len = strlen(_self->h2_uri_path) +
                            sizeof(OUTPUT_DNSSIM_HTTP_GET_TEMPLATE) +
                            (content->len * 4) / 3 + 3;  /* upper limit of base64 encoding */
    if (path_len >= _MAX_URI_LEN) {
        self->discarded++;
        linfo("http2: uri path with query too long, query discarded");
        return 0;
    }
    char path[path_len];
    strncpy(path, _self->h2_uri_path, path_len);
    strncat(path, OUTPUT_DNSSIM_HTTP_GET_TEMPLATE, path_len);

    size_t tmp_path_len = strlen(path);
    int32_t ret = base64url_encode(content->payload, content->len,
        (uint8_t *)(path + tmp_path_len), path_len - tmp_path_len - 1);
    if (ret < 0) {
        self->discarded++;
        linfo("http2: base64url encode of query failed, query discarded");
        return 0;
    }

    nghttp2_nv hdrs[] = {
        OUTPUT_DNSSIM_MAKE_NV2(":method", "GET"),
        OUTPUT_DNSSIM_MAKE_NV2(":scheme", "https"),
        OUTPUT_DNSSIM_MAKE_NV(":authority", _self->h2_uri_authority, strlen(_self->h2_uri_authority)),
        OUTPUT_DNSSIM_MAKE_NV(":path", path, tmp_path_len + ret),
        OUTPUT_DNSSIM_MAKE_NV2("accept", "application/dns-message"),
    };

    qry->stream_id = nghttp2_submit_request(conn->http2->session, NULL, hdrs, sizeof(hdrs) / sizeof(nghttp2_nv), NULL, NULL);

    if (qry->stream_id < 0) {
        mldebug("http2 (%p): failed to submit request: %s", conn->http2->session, nghttp2_strerror(qry->stream_id));
        return -1;
    }
    mldebug("http2 (%p): GET %s", conn->http2->session, path);
    conn->http2->open_streams++;
    _http2_check_max_streams(conn);

    ret = nghttp2_session_send(conn->http2->session);
    if (ret < 0) {
        mldebug("http2 (%p): failed session send: %s", conn->http2->session, nghttp2_strerror(ret));
        return -1;
    }

    return 0;
}

static int _http2_send_query_post(_output_dnssim_connection_t* conn, _output_dnssim_query_tcp_t* qry)
{
    mlassert(conn, "conn can't be null");
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.req, "req can't be null");
    mlassert(qry->qry.req->payload, "payload can't be null");
    mlassert(qry->qry.req->payload->len <= MAX_DNSMSG_SIZE, "payload too big");
    mlassert(conn->client, "conn must be associated with client");
    mlassert(conn->client->dnssim, "client must have dnssim");

    output_dnssim_t* self = conn->client->dnssim;

    core_object_payload_t* content = qry->qry.req->payload;

    int window_size = nghttp2_session_get_remote_window_size(conn->http2->session);
    if (content->len > window_size) {
           mldebug("http2 (%p): insufficient remote window size, deferring", conn->http2->session);
           return 0;
    }

    char content_length[6];  /* max dnslen "65535" */
    int content_length_len = sprintf(content_length, "%ld", content->len);

    nghttp2_nv hdrs[] = {
        OUTPUT_DNSSIM_MAKE_NV2(":method", "POST"),
        OUTPUT_DNSSIM_MAKE_NV2(":scheme", "https"),
        OUTPUT_DNSSIM_MAKE_NV(":authority", _self->h2_uri_authority, strlen(_self->h2_uri_authority)),
        OUTPUT_DNSSIM_MAKE_NV(":path", _self->h2_uri_path, strlen(_self->h2_uri_path)),
        OUTPUT_DNSSIM_MAKE_NV2("accept", "application/dns-message"),
        OUTPUT_DNSSIM_MAKE_NV2("content-type", "application/dns-message"),
        OUTPUT_DNSSIM_MAKE_NV("content-length", content_length, content_length_len)
    };

    _output_dnssim_https2_data_provider_t data = {
        .buf = content->payload,
        .len = content->len
    };

    nghttp2_data_provider data_provider = {
        .source.ptr = &data,
        .read_callback = _http2_on_data_provider_read
    };

    qry->stream_id = nghttp2_submit_request(conn->http2->session, NULL, hdrs, sizeof(hdrs) / sizeof(nghttp2_nv), &data_provider, NULL);

    if (qry->stream_id < 0) {
        mldebug("http2 (%p): failed to submit request: %s", conn->http2->session, nghttp2_strerror(qry->stream_id));
        return -1;
    }
    mldebug("http2 (%p): POST payload len=%ld", conn->http2->session, content->len);
    conn->http2->open_streams++;
    _http2_check_max_streams(conn);

    window_size = nghttp2_session_get_stream_remote_window_size(conn->http2->session, qry->stream_id);
    mlassert(content->len <= window_size,
        "unsupported: http2 stream window size (%ld B) is smaller than dns payload (%ld B)",
        window_size, content->len);

    int ret = nghttp2_session_send(conn->http2->session);
    if (ret < 0) {
        mldebug("http2 (%p): failed session send: %s", conn->http2->session, nghttp2_strerror(ret));
        return -1;
    }

    return 0;
}

void _output_dnssim_https2_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_tcp_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE, "qry must be pending write");
    mlassert(conn, "conn can't be null");
    mlassert(conn->state == _OUTPUT_DNSSIM_CONN_ACTIVE, "connection state != ACTIVE");
    mlassert(conn->http2, "conn must have http2 ctx");
    mlassert(conn->http2->session, "conn must have http2 session");
    mlassert(conn->client, "conn must be associated with client");
    mlassert(conn->client->pending, "conn has no pending queries");
    mlassert(conn->client->dnssim, "client must have dnssim");

    int ret;
    output_dnssim_t* self = conn->client->dnssim;

    if (!nghttp2_session_check_request_allowed(conn->http2->session)) {
       mldebug("http2 (%p): request not allowed", conn->http2->session);
       _output_dnssim_conn_close(conn);
       return;
    }

    switch (_self->h2_method) {
    case OUTPUT_DNSSIM_H2_POST:
        ret = _http2_send_query_post(conn, qry);
        break;
    case OUTPUT_DNSSIM_H2_GET:
        ret = _http2_send_query_get(conn, qry);
        break;
    default:
        lfatal("http2: unsupported method");
    }

    if (ret < 0) {
        _output_dnssim_conn_close(conn);
        return;
    }

    qry->conn = conn;
    _ll_remove(conn->client->pending, &qry->qry);
    _ll_append(conn->sent, &qry->qry);

    /* Stop idle timer, since there are queries to answer now. */
    if (conn->idle_timer != NULL) {
        conn->is_idle = false;
        uv_timer_stop(conn->idle_timer);
    }

    qry->qry.state = _OUTPUT_DNSSIM_QUERY_SENT;
}

#endif

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

#define MIN(a,b) (((a)<(b))?(a):(b))			/** Minimum of two numbers **/

static core_log_t _log = LOG_T_INIT("output.dnssim");

struct async_write_ctx {
	uv_write_t write_req;
	_output_dnssim_connection_t* conn;
	char buf[];
};

static int _tls_handshake(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->tls, "conn must have tls context");
    mlassert(conn->state <= _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE, "conn in invalid state");

    conn->state = _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE;

	int err = gnutls_handshake(conn->tls->session);
	if (err == GNUTLS_E_SUCCESS) {
        _output_dnssim_conn_activate(conn);
        return 0;
	} else if (err == GNUTLS_E_AGAIN) {
		return GNUTLS_E_AGAIN;
	} else if (gnutls_error_is_fatal(err)) {
        return err;
	}
	return 0;
}

void _output_dnssim_tls_process_input_data(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->client, "conn must have client");
    mlassert(conn->client->dnssim, "client must have dnssim");
    mlassert(conn->tls, "conn must have tls ctx");

    output_dnssim_t* self = conn->client->dnssim;

	/* Ensure TLS handshake is performed before receiving data.
	 * See https://www.gnutls.org/manual/html_node/TLS-handshake.html */
	while (conn->state <= _OUTPUT_DNSSIM_CONN_TLS_HANDSHAKE) {
		int err = _tls_handshake(conn);
		if (err == GNUTLS_E_AGAIN) {
			return; /* Wait for more data */
        } else if (err == GNUTLS_E_FATAL_ALERT_RECEIVED) {
            gnutls_alert_description_t alert = gnutls_alert_get(conn->tls->session);
            mlwarning("gnutls_handshake failed: %s", gnutls_alert_get_name(alert));
            _output_dnssim_conn_close(conn);
            return;
		} else if (err < 0) {
            mlwarning("gnutls_handshake failed: %s", gnutls_strerror_name(err));
            _output_dnssim_conn_close(conn);
            return;
		}
	}

	/* See https://gnutls.org/manual/html_node/Data-transfer-and-termination.html#Data-transfer-and-termination */
	while (true) {
		ssize_t count = gnutls_record_recv(conn->tls->session, _self->wire_buf, WIRE_BUF_SIZE);
        if (count > 0) {
            _output_dnssim_read_dns_stream(conn, count, _self->wire_buf);
        } else if (count == GNUTLS_E_AGAIN) {
			if (conn->tls->buf_pos == conn->tls->buf_len) {
				/* See https://www.gnutls.org/manual/html_node/Asynchronous-operation.html */
				break; /* No more data available in this libuv buffer */
			}
			continue;
		} else if (count == GNUTLS_E_INTERRUPTED) {
			continue;
		} else if (count == GNUTLS_E_REHANDSHAKE) {
            // TODO implement rehandshake?
			continue;
		} else if (count < 0) {
            mlwarning("gnutls_record_recv failed: %s", gnutls_strerror_name(count));
            _output_dnssim_conn_close(conn);
            return;
		} else if (count == 0) {
			break;
		}
	}
    mlassert(conn->tls->buf_len == conn->tls->buf_pos, "tls didn't read the entire buffer");

}

static ssize_t _tls_pull(gnutls_transport_ptr_t ptr, void *buf, size_t len)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)ptr;
    mlassert(conn != NULL, "conn is null");
    mlassert(conn->tls != NULL, "conn must have tls ctx");

	ssize_t	avail = conn->tls->buf_len - conn->tls->buf_pos;
	if (conn->tls->buf_pos >= conn->tls->buf_len) {
		errno = EAGAIN;
		return -1;
	}

	ssize_t	transfer = MIN(avail, len);
	memcpy(buf, conn->tls->buf + conn->tls->buf_pos, transfer);
	conn->tls->buf_pos += transfer;
	return transfer;
}

static void _tls_on_write_complete(uv_write_t *req, int status)
{
	mlassert(req->data != NULL, "uv_write req has no data pointer");
	struct async_write_ctx *async_ctx = (struct async_write_ctx *)req->data;
	_output_dnssim_connection_t* conn = async_ctx->conn;
    mlassert(conn, "conn is nil");
    mlassert(conn->tls, "conn must have tls ctx");
    mlassert(conn->tls->write_queue_size > 0, "invalid write_queue_size: %d", conn->tls->write_queue_size);
	conn->tls->write_queue_size -= 1;
	free(req->data);

    if (status < 0)
        _output_dnssim_conn_close(conn);
}

static ssize_t _tls_vec_push(gnutls_transport_ptr_t ptr, const giovec_t * iov, int iovcnt)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)ptr;
    mlassert(conn != NULL, "conn is null");
    mlassert(conn->tls != NULL, "conn must have tls ctx");

	if (iovcnt == 0)
		return 0;

	/*
	 * This is a little bit complicated. There are two different writes:
	 * 1. Immediate, these don't need to own the buffered data and return immediately
	 * 2. Asynchronous, these need to own the buffers until the write completes
	 * In order to avoid copying the buffer, an immediate write is tried first if possible.
	 * If it isn't possible to write the data without queueing, an asynchronous write
	 * is created (with copied buffered data).
	 */

	size_t total_len = 0;
	uv_buf_t uv_buf[iovcnt];
	for (int i = 0; i < iovcnt; ++i) {
		uv_buf[i].base = iov[i].iov_base;
		uv_buf[i].len = iov[i].iov_len;
		total_len += iov[i].iov_len;
	}

	/* Try to perform the immediate write first to avoid copy */
	int ret = 0;
	if (conn->tls->write_queue_size == 0) {
		ret = uv_try_write((uv_stream_t*)conn->handle, uv_buf, iovcnt);
		/* from libuv documentation -
		   uv_try_write will return either:
		     > 0: number of bytes written (can be less than the supplied buffer size).
		     < 0: negative error code (UV_EAGAIN is returned if no data can be sent immediately).
		*/
		if (ret == total_len) {
			/* All the data were buffered by libuv.
			 * Return. */
			return ret;
		}

		if (ret < 0 && ret != UV_EAGAIN) {
			/* uv_try_write() has returned error code other then UV_EAGAIN.
			 * Return. */
			errno = EIO;
			return -1;
		}
		/* Since we are here expression below is true
		 * (ret != total_len) && (ret >= 0 || ret == UV_EAGAIN)
		 * or the same
		 * (ret != total_len && ret >= 0) || (ret != total_len && ret == UV_EAGAIN)
		 * i.e. either occurs partial write or UV_EAGAIN.
		 * Proceed and copy data amount to owned memory and perform async write.
		 */
		if (ret == UV_EAGAIN) {
			/* No data were buffered, so we must buffer all the data. */
			ret = 0;
		}
	}

	/* Fallback when the queue is full, and it's not possible to do an immediate write */
	char *p = malloc(sizeof(struct async_write_ctx) + total_len - ret);
	if (p != NULL) {
		struct async_write_ctx *async_ctx = (struct async_write_ctx *)p;
		async_ctx->conn = conn;
		char *buf = async_ctx->buf;
		/* Skip data written in the partial write */
		size_t to_skip = ret;
		/* Copy the buffer into owned memory */
		size_t off = 0;
		for (int i = 0; i < iovcnt; ++i) {
			if (to_skip > 0) {
				/* Ignore current buffer if it's all skipped */
				if (to_skip >= uv_buf[i].len) {
					to_skip -= uv_buf[i].len;
					continue;
				}
				/* Skip only part of the buffer */
				uv_buf[i].base += to_skip;
				uv_buf[i].len -= to_skip;
				to_skip = 0;
			}
			memcpy(buf + off, uv_buf[i].base, uv_buf[i].len);
			off += uv_buf[i].len;
		}
		uv_buf[0].base = buf;
		uv_buf[0].len = off;

		/* Create an asynchronous write request */
		uv_write_t *write_req = &async_ctx->write_req;
		memset(write_req, 0, sizeof(uv_write_t));
		write_req->data = p;

		/* Perform an asynchronous write with a callback */
		if (uv_write(write_req, (uv_stream_t*)conn->handle, uv_buf, 1, _tls_on_write_complete) == 0) {
			ret = total_len;
			conn->tls->write_queue_size += 1;
		} else {
			free(p);
			errno = EIO;
			ret = -1;
		}
	} else {
		errno = ENOMEM;
		ret = -1;
	}

	return ret;
}


int _output_dnssim_tls_init(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->tls == NULL, "conn already has tls context");

    int ret;
    mlfatal_oom(conn->tls = malloc(sizeof(_output_dnssim_tls_ctx_t)));
    conn->tls->buf = NULL;
    conn->tls->buf_len = 0;
    conn->tls->buf_pos = 0;
    conn->tls->write_queue_size = 0;

	ret = gnutls_init(&conn->tls->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
    if (ret < 0) {
        mldebug("failed gnutls_init() (%s)", gnutls_strerror(ret));
        return ret;
    }

    output_dnssim_t* self = conn->client->dnssim;
    ret = gnutls_priority_set(conn->tls->session, _self->tls_priority);
    if (ret < 0) {
        mldebug("failed gnutls_priority_set() (%s)", gnutls_strerror(ret));
        return ret;
    }

    ret = gnutls_credentials_set(conn->tls->session, GNUTLS_CRD_CERTIFICATE, _self->tls_cred);
    if (ret < 0) {
        mldebug("failed gnutls_credentials_set() (%s)", gnutls_strerror(ret));
        return ret;
    }

	gnutls_transport_set_pull_function(conn->tls->session, _tls_pull);
	gnutls_transport_set_vec_push_function(conn->tls->session, _tls_vec_push);
	gnutls_transport_set_ptr(conn->tls->session, conn);

	return 0;
}

// TODO so far this is the same as the tcp function (except qry.transport)
int _output_dnssim_create_query_tls(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();
    lassert(req, "req is nil");
    lassert(req->client, "request must have a client associated with it");

    _output_dnssim_query_tcp_t* qry;  // TODO do tls queries need other struct than tcp?

    lfatal_oom(qry = calloc(1, sizeof(_output_dnssim_query_tcp_t)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_TLS;
    qry->qry.req       = req;
    qry->qry.state     = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE;
    req->qry           = &qry->qry; // TODO change when adding support for multiple Qs for req
    _ll_append(req->client->pending, &qry->qry);

    return _output_dnssim_handle_pending_queries(req->client);
}

void _output_dnssim_close_query_tls(_output_dnssim_query_tcp_t* qry)
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

    _ll_remove(req->qry, &qry->qry);
    free(qry);
}

void _output_dnssim_tls_close(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->tls, "conn must have tls ctx");

    /*
     * TODO: proper gnutls_bye() might be needed to allow session resumption
     * https://gnutls.org/manual/html_node/Data-transfer-and-termination.html#Data-transfer-and-termination
     */
    gnutls_deinit(conn->tls->session);
    _output_dnssim_tcp_close(conn);
}

void _output_dnssim_tls_write_query(_output_dnssim_connection_t* conn, _output_dnssim_query_tcp_t* qry)
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

    core_object_payload_t* payload = (core_object_payload_t*)qry->qry.req->dns_q->obj_prev;
    uint16_t len = htons(payload->len);

	gnutls_record_cork(conn->tls->session);
	ssize_t count = 0;
	if ((count = gnutls_record_send(conn->tls->session, &len, sizeof(len)) < 0) ||
	    (count = gnutls_record_send(conn->tls->session, payload->payload, payload->len) < 0)) {
        mlwarning("gnutls_record_send failed: %s", gnutls_strerror_name(count));
        _output_dnssim_conn_close(conn);
        return;
	}

	const ssize_t submitted = sizeof(len) + payload->len;

	int ret = gnutls_record_uncork(conn->tls->session, GNUTLS_RECORD_WAIT);
	if (gnutls_error_is_fatal(ret)) {
        mlinfo("gnutls_record_uncorck failed: %s", gnutls_strerror_name(ret));
        _output_dnssim_conn_close(conn);
        return;
	}

	if (ret != submitted) {
        mlwarning("gnutls_record_uncork didn't send all data");
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

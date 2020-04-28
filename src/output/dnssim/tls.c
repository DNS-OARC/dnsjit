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

static core_log_t _log = LOG_T_INIT("output.dnssim");


void _tls_process_input_data()
{

}

//static ssize_t _tls_pull(gnutls_transport_ptr_t h, void *buf, size_t len)
//{
//	struct tls_common_ctx *t = (struct tls_common_ctx *)h;
//	assert(t != NULL);
//
//	ssize_t	avail = t->nread - t->consumed;
//	DEBUG_MSG("[%s] pull wanted: %zu available: %zu\n",
//		  t->client_side ? "tls_client" : "tls", len, avail);
//	if (t->nread <= t->consumed) {
//		errno = EAGAIN;
//		return -1;
//	}
//
//	ssize_t	transfer = MIN(avail, len);
//	memcpy(buf, t->buf + t->consumed, transfer);
//	t->consumed += transfer;
//	return transfer;
//}
//
int _output_dnssim_tls_init(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn is nil");
    mlassert(conn->tls == NULL, "conn already has tls context");

    int ret;
    mlfatal_oom(conn->tls = malloc(sizeof(_output_dnssim_tls_ctx_t)));

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

    ret = gnutls_credentials_set(conn->tls->session, GNUTLS_CRD_CERTIFICATE, &_self->tls_cred);
    if (ret < 0) {
        mldebug("failed gnutls_credentials_set() (%s)", gnutls_strerror(ret));
        return ret;
    }

    // TODO implement
	// gnutls_transport_set_pull_function(tls->c.tls_session, kres_gnutls_pull);
	// gnutls_transport_set_vec_push_function(tls->c.tls_session, kres_gnutls_vec_push);
	// gnutls_transport_set_ptr(conn->tls->session, conn);

	return 0;
}

//static ssize_t _tls_vec_push(gnutls_transport_ptr_t h, const giovec_t * iov, int iovcnt)
//{
//	struct tls_common_ctx *t = (struct tls_common_ctx *)h;
//
//	if (t == NULL) {
//		errno = EFAULT;
//		return -1;
//	}
//
//	if (iovcnt == 0) {
//		return 0;
//	}
//
//	assert(t->session);
//	uv_stream_t *handle = (uv_stream_t *)session_get_handle(t->session);
//	assert(handle && handle->type == UV_TCP);
//
//	/*
//	 * This is a little bit complicated. There are two different writes:
//	 * 1. Immediate, these don't need to own the buffered data and return immediately
//	 * 2. Asynchronous, these need to own the buffers until the write completes
//	 * In order to avoid copying the buffer, an immediate write is tried first if possible.
//	 * If it isn't possible to write the data without queueing, an asynchronous write
//	 * is created (with copied buffered data).
//	 */
//
//	size_t total_len = 0;
//	uv_buf_t uv_buf[iovcnt];
//	for (int i = 0; i < iovcnt; ++i) {
//		uv_buf[i].base = iov[i].iov_base;
//		uv_buf[i].len = iov[i].iov_len;
//		total_len += iov[i].iov_len;
//	}
//
//	/* Try to perform the immediate write first to avoid copy */
//	int ret = 0;
//	if (stream_queue_is_empty(t)) {
//		ret = uv_try_write(handle, uv_buf, iovcnt);
//		DEBUG_MSG("[%s] push %zu <%p> = %d\n",
//		    t->client_side ? "tls_client" : "tls", total_len, h, ret);
//		/* from libuv documentation -
//		   uv_try_write will return either:
//		     > 0: number of bytes written (can be less than the supplied buffer size).
//		     < 0: negative error code (UV_EAGAIN is returned if no data can be sent immediately).
//		*/
//		if (ret == total_len) {
//			/* All the data were buffered by libuv.
//			 * Return. */
//			return ret;
//		}
//
//		if (ret < 0 && ret != UV_EAGAIN) {
//			/* uv_try_write() has returned error code other then UV_EAGAIN.
//			 * Return. */
//			ret = -1;
//			errno = EIO;
//			return ret;
//		}
//		/* Since we are here expression below is true
//		 * (ret != total_len) && (ret >= 0 || ret == UV_EAGAIN)
//		 * or the same
//		 * (ret != total_len && ret >= 0) || (ret != total_len && ret == UV_EAGAIN)
//		 * i.e. either occurs partial write or UV_EAGAIN.
//		 * Proceed and copy data amount to owned memory and perform async write.
//		 */
//		if (ret == UV_EAGAIN) {
//			/* No data were buffered, so we must buffer all the data. */
//			ret = 0;
//		}
//	}
//
//	/* Fallback when the queue is full, and it's not possible to do an immediate write */
//	char *p = malloc(sizeof(struct async_write_ctx) + total_len - ret);
//	if (p != NULL) {
//		struct async_write_ctx *async_ctx = (struct async_write_ctx *)p;
//		/* Save pointer to session tls context */
//		async_ctx->t = t;
//		char *buf = async_ctx->buf;
//		/* Skip data written in the partial write */
//		size_t to_skip = ret;
//		/* Copy the buffer into owned memory */
//		size_t off = 0;
//		for (int i = 0; i < iovcnt; ++i) {
//			if (to_skip > 0) {
//				/* Ignore current buffer if it's all skipped */
//				if (to_skip >= uv_buf[i].len) {
//					to_skip -= uv_buf[i].len;
//					continue;
//				}
//				/* Skip only part of the buffer */
//				uv_buf[i].base += to_skip;
//				uv_buf[i].len -= to_skip;
//				to_skip = 0;
//			}
//			memcpy(buf + off, uv_buf[i].base, uv_buf[i].len);
//			off += uv_buf[i].len;
//		}
//		uv_buf[0].base = buf;
//		uv_buf[0].len = off;
//
//		/* Create an asynchronous write request */
//		uv_write_t *write_req = &async_ctx->write_req;
//		memset(write_req, 0, sizeof(uv_write_t));
//		write_req->data = p;
//
//		/* Perform an asynchronous write with a callback */
//		if (uv_write(write_req, handle, uv_buf, 1, on_write_complete) == 0) {
//			ret = total_len;
//			t->write_queue_size += 1;
//		} else {
//			free(p);
//			errno = EIO;
//			ret = -1;
//		}
//	} else {
//		errno = ENOMEM;
//		ret = -1;
//	}
//
//	DEBUG_MSG("[%s] queued %zu <%p> = %d\n",
//	    t->client_side ? "tls_client" : "tls", total_len, h, ret);
//
//	return ret;
//}

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

    // TODO call _handle_pending_queries or tls equivalent
    //return _handle_pending_queries(req->client);
    return 0;
}

void _output_dnssim_close_query_tls(_output_dnssim_query_tcp_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->qry.req, "query must be part of a request");
    _output_dnssim_request_t* req = qry->qry.req;
    mlassert(req->client, "request must belong to a client");

    mlfatal("TODO: handle closing tls queries");
}

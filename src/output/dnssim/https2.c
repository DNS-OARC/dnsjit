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

static core_log_t _log = LOG_T_INIT("output.dnssim");

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

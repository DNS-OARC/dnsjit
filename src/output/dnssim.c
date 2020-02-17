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
#include "core/assert.h"
#include "core/object/ip.h"
#include "core/object/ip6.h"
#include "core/object/payload.h"
#include "core/object/dns.h"

#define _ll_append(list, element) \
    { \
        if ((list) == NULL) \
            (list) = (element); \
        else if ((element) != NULL) \
        { \
            glassert((element)->next == NULL, "element->next must be null when appending"); \
            typeof(list) _current = (list); \
            while (_current->next != NULL) \
                _current = _current->next; \
            _current->next = element; \
        } \
    }

#define _ll_remove_template(list, element, strict) \
    { \
        if (strict) \
            glassert((list), "list can't be null when removing elements"); \
        if ((list) != NULL && (element) != NULL) { \
            if ((list) == (element)) { \
                (list) = (element)->next; \
                (element)->next = NULL; \
            } else { \
                typeof(list) _current = (list); \
                while (_current != NULL && _current->next != (element)) { \
                    if (strict) \
                        glassert((_current->next), "list doesn't contain the element to be removed"); \
                    _current = _current->next; \
                } \
                if (_current != NULL) { \
                    _current->next = (element)->next; \
                    (element)->next = NULL; \
                } \
            } \
        } \
    }

#define _ll_remove(list, element) _ll_remove_template((list), (element), true)
#define _ll_try_remove(list, element) _ll_remove_template((list), (element), false)

typedef struct _output_dnssim_s _output_dnssim_t;
typedef struct _output_dnssim_client_s _output_dnssim_client_t;
typedef struct _output_dnssim_request_s _output_dnssim_request_t;
typedef struct _output_dnssim_connection_s _output_dnssim_connection_t;
typedef struct _output_dnssim_query_s _output_dnssim_query_t;
typedef struct _output_dnssim_query_udp_s _output_dnssim_query_udp_t;
typedef struct _output_dnssim_query_tcp_s _output_dnssim_query_tcp_t;
typedef struct _output_dnssim_source_s _output_dnssim_source_t;

struct _output_dnssim_source_s {
    _output_dnssim_source_t* next;
    struct sockaddr_storage addr;
};

typedef enum _output_dnssim_read_state {
    _OUTPUT_DNSSIM_READ_STATE_CLEAN,
    _OUTPUT_DNSSIM_READ_STATE_DNSLEN,
    _OUTPUT_DNSSIM_READ_STATE_DNSMSG,
    _OUTPUT_DNSSIM_READ_STATE_INVALID
} _output_dnssim_read_state_t;

struct _output_dnssim_connection_s {
    _output_dnssim_connection_t* next;

    uv_tcp_t handle;
    uv_connect_t conn_req;

    /* List of queries that have been queued (pending write callback). */
    _output_dnssim_query_t* queued;

    /* List of queries that have been sent over this connection. */
    _output_dnssim_query_t* sent;

    _output_dnssim_client_t* client;

    enum {
        _OUTPUT_DNSSIM_CONN_INITIALIZED,
        _OUTPUT_DNSSIM_CONN_CONNECTING,
        // _OUTPUT_DNSSIM_CONN_CONNECTED,
        _OUTPUT_DNSSIM_CONN_ACTIVE,
        _OUTPUT_DNSSIM_CONN_CLOSING
    } state;

    _output_dnssim_read_state_t read_state;

    /* Total length of the expected stream data (either 2 for dnslen, or dnslen itself). */
    size_t recv_len;

    /* Current position in the receive buffer. */
    size_t recv_pos;

    /* Receive buffer used for incomplete messages or dnslen. */
    char* recv_data;
    bool recv_free_after_use;
};

struct _output_dnssim_client_s {
    /* List of connections.
     * Multiple connections may be used (e.g. some are already closed for writing).
     */
    _output_dnssim_connection_t* conn;

    /* List of queries that are pending to be sent over any available connection. */
    _output_dnssim_query_t* pending;
};

struct _output_dnssim_s {
    output_dnssim_t pub;

    output_dnssim_transport_t transport;
    uv_loop_t loop;
    struct sockaddr_storage target;
    _output_dnssim_source_t* source;

    _output_dnssim_client_t* client_arr;

    uv_timer_t stats_timer;

    void (*create_request)(output_dnssim_t*, _output_dnssim_client_t*,
        core_object_payload_t*);
};

struct _output_dnssim_query_s {
    _output_dnssim_query_t* next;
    output_dnssim_transport_t transport;
    _output_dnssim_request_t* req;

    /* Query state, currently used only for TCP. */
    enum {
        _OUTPUT_DNSSIM_QUERY_PENDING_WRITE,
        _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB,
        _OUTPUT_DNSSIM_QUERY_SENT
    } state;
};

struct _output_dnssim_query_udp_s {
    _output_dnssim_query_t qry;
    uv_udp_t* handle;
    uv_buf_t buf;
    //uv_timer_t* qry_retransmit;
};

struct _output_dnssim_query_tcp_s {
    _output_dnssim_query_t qry;
    _output_dnssim_connection_t* conn;

    uv_write_t write_req;
    uv_buf_t bufs[2];
};

struct _output_dnssim_request_s {
    _output_dnssim_query_t* qry;
    _output_dnssim_client_t* client;
    core_object_payload_t* payload;
    core_object_dns_t* dns_q;
    uint64_t created_at;
    uint64_t ended_at;
    uv_timer_t* timeout;
    uint8_t timeout_closing;
    uint8_t ongoing;
    // enum {
    //     _OUTPUT_DNSSIM_
    output_dnssim_t* dnssim;
};

static core_log_t _log = LOG_T_INIT("output.dnssim");
static output_dnssim_t _defaults = {
    LOG_T_INIT_OBJ("output.dnssim"),
    0, 0, 0,
    NULL, NULL, NULL,
    0, 0,
    2000, 0
};

static output_dnssim_stats_t _stats_defaults = {
    NULL, NULL,
    NULL,
    0, 0,
    0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// forward declarations
static void _close_query_udp(_output_dnssim_query_udp_t* qry);
static void _close_query_tcp(_output_dnssim_query_tcp_t* qry);
static void _close_request_timeout_cb(uv_handle_t* handle);
static void _close_request_timeout(uv_timer_t* handle);

uint64_t _now_ms()
{
#if HAVE_CLOCK_NANOSLEEP
    struct timespec ts;
    uint64_t now_ms;
    if (clock_gettime(CLOCK_REALTIME, &ts)) {
        mlfatal("clock_gettime()");
    }
    now_ms = ts.tv_sec * 1000;
    now_ms += ts.tv_nsec / 1000000;
    return now_ms;
#else
    mlfatal("clock_gettime() not available");
#endif
}

core_log_t* output_dnssim_log()
{
    return &_log;
}

#define _self ((_output_dnssim_t*)self)
#define _ERR_MALFORMED -2
#define _ERR_MSGID -3
#define _ERR_TC -4


/*** request/query ***/
static void _maybe_free_request(_output_dnssim_request_t* req)
{
    if (req->qry == NULL && req->timeout == NULL) {
        if (req->dnssim->free_after_use) {
            core_object_payload_free(req->payload);
        }
        core_object_dns_free(req->dns_q);
        free(req);
    }
}

static void _close_query(_output_dnssim_query_t* qry)
{
    switch(qry->transport) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
        _close_query_udp((_output_dnssim_query_udp_t*)qry);
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        _close_query_tcp((_output_dnssim_query_tcp_t*)qry);
        break;
    default:
        mlnotice("failed to close query: unsupported transport");
        break;
    }
}

static void _close_request(_output_dnssim_request_t* req)
{
    if (req == NULL) {
        return;
    }
    if (req->ongoing) {
        req->ongoing = 0;
        req->dnssim->ongoing--;
    }
    if (req->timeout != NULL) {
        _close_request_timeout(req->timeout);
    }
    // finish any queries in flight
    _output_dnssim_query_t* qry = req->qry;
    while (qry != NULL) {
        _close_query(qry);
        qry = qry->next;
    }
    _maybe_free_request(req);
}

static void _close_request_timeout_cb(uv_handle_t* handle)
{
    _output_dnssim_request_t* req = (_output_dnssim_request_t*)handle->data;
    free(handle);
    req->timeout = NULL;
    _close_request(req);
}

static void _close_request_timeout(uv_timer_t* handle)
{
    _output_dnssim_request_t* req = (_output_dnssim_request_t*)handle->data;

    if (!req->timeout_closing) {
        req->timeout_closing = 1;

        uint64_t latency = req->ended_at - req->created_at;
        mlassert(latency <= req->dnssim->timeout_ms, "invalid latency value");
        req->dnssim->stats_current->latency[latency]++;
        req->dnssim->stats_sum->latency[latency]++;

        uv_timer_stop(handle);
        uv_close((uv_handle_t*)handle, _close_request_timeout_cb);
    }
}

static void _request_answered(_output_dnssim_request_t* req, core_object_dns_t* msg)
{
    req->dnssim->stats_sum->answers++;
    req->dnssim->stats_current->answers++;

    switch(msg->rcode) {
    case CORE_OBJECT_DNS_RCODE_NOERROR:
        req->dnssim->stats_sum->rcode_noerror++;
        req->dnssim->stats_current->rcode_noerror++;
        break;
    case CORE_OBJECT_DNS_RCODE_FORMERR:
        req->dnssim->stats_sum->rcode_formerr++;
        req->dnssim->stats_current->rcode_formerr++;
        break;
    case CORE_OBJECT_DNS_RCODE_SERVFAIL:
        req->dnssim->stats_sum->rcode_servfail++;
        req->dnssim->stats_current->rcode_servfail++;
        break;
    case CORE_OBJECT_DNS_RCODE_NXDOMAIN:
        req->dnssim->stats_sum->rcode_nxdomain++;
        req->dnssim->stats_current->rcode_nxdomain++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTIMP:
        req->dnssim->stats_sum->rcode_notimp++;
        req->dnssim->stats_current->rcode_notimp++;
        break;
    case CORE_OBJECT_DNS_RCODE_REFUSED:
        req->dnssim->stats_sum->rcode_refused++;
        req->dnssim->stats_current->rcode_refused++;
        break;
    case CORE_OBJECT_DNS_RCODE_YXDOMAIN:
        req->dnssim->stats_sum->rcode_yxdomain++;
        req->dnssim->stats_current->rcode_yxdomain++;
        break;
    case CORE_OBJECT_DNS_RCODE_YXRRSET:
        req->dnssim->stats_sum->rcode_yxrrset++;
        req->dnssim->stats_current->rcode_yxrrset++;
        break;
    case CORE_OBJECT_DNS_RCODE_NXRRSET:
        req->dnssim->stats_sum->rcode_nxrrset++;
        req->dnssim->stats_current->rcode_nxrrset++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTAUTH:
        req->dnssim->stats_sum->rcode_notauth++;
        req->dnssim->stats_current->rcode_notauth++;
        break;
    case CORE_OBJECT_DNS_RCODE_NOTZONE:
        req->dnssim->stats_sum->rcode_notzone++;
        req->dnssim->stats_current->rcode_notzone++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADVERS:
        req->dnssim->stats_sum->rcode_badvers++;
        req->dnssim->stats_current->rcode_badvers++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADKEY:
        req->dnssim->stats_sum->rcode_badkey++;
        req->dnssim->stats_current->rcode_badkey++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADTIME:
        req->dnssim->stats_sum->rcode_badtime++;
        req->dnssim->stats_current->rcode_badtime++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADMODE:
        req->dnssim->stats_sum->rcode_badmode++;
        req->dnssim->stats_current->rcode_badmode++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADNAME:
        req->dnssim->stats_sum->rcode_badname++;
        req->dnssim->stats_current->rcode_badname++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADALG:
        req->dnssim->stats_sum->rcode_badalg++;
        req->dnssim->stats_current->rcode_badalg++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADTRUNC:
        req->dnssim->stats_sum->rcode_badtrunc++;
        req->dnssim->stats_current->rcode_badtrunc++;
        break;
    case CORE_OBJECT_DNS_RCODE_BADCOOKIE:
        req->dnssim->stats_sum->rcode_badcookie++;
        req->dnssim->stats_current->rcode_badcookie++;
        break;
    default:
        req->dnssim->stats_sum->rcode_other++;
        req->dnssim->stats_current->rcode_other++;
    }
}


/*** UDP dnssim ***/
static int _process_udp_response(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf)
{
    _output_dnssim_query_udp_t* qry = (_output_dnssim_query_udp_t*)handle->data;
    _output_dnssim_request_t* req = qry->qry.req;
    core_object_payload_t payload = CORE_OBJECT_PAYLOAD_INIT(NULL);
    core_object_dns_t dns_a = CORE_OBJECT_DNS_INIT(&payload);

    payload.payload = buf->base;
    payload.len = nread;

    dns_a.obj_prev = (core_object_t*)&payload;
    int ret = core_object_dns_parse_header(&dns_a);
    if (ret != 0) {
        mldebug("udp response malformed");
        return _ERR_MALFORMED;
    }
    if (dns_a.id != req->dns_q->id) {
        mldebug("udp response msgid mismatch %x(q) != %x(a)", req->dns_q->id, dns_a.id);
        return _ERR_MSGID;
    }
    if (dns_a.tc == 1) {
        mldebug("udp response has TC=1");
        return _ERR_TC;
    }

    req->ended_at = uv_now(&((_output_dnssim_t*)req->dnssim)->loop);
    if (req->ended_at > (req->created_at + req->dnssim->timeout_ms)) {
        req->ended_at = req->created_at + req->dnssim->timeout_ms;
    }

    _request_answered(req, &dns_a);
    _close_request(req);
    return 0;
}

static void _uv_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    mlfatal_oom(buf->base = malloc(suggested_size));
    buf->len = suggested_size;
}

static void _query_udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
    const struct sockaddr* addr, unsigned flags)
{
    if (nread > 0) {
        mldebug("udp recv: %d", nread);

        // TODO handle TC=1
        _process_udp_response(handle, nread, buf);
    }

    if (buf->base != NULL) {
        free(buf->base);
    }
}

static void _close_query_udp_cb(uv_handle_t* handle)
{
    _output_dnssim_query_udp_t* qry = (_output_dnssim_query_udp_t*)handle->data;
    _output_dnssim_request_t* req = qry->qry.req;

    free(qry->handle);

    _ll_remove(req->qry, &qry->qry);
    free(qry);

    if (req->qry == NULL)
        _maybe_free_request(req);
}

static void _close_query_udp(_output_dnssim_query_udp_t* qry)
{
    int ret;

    ret = uv_udp_recv_stop(qry->handle);
    if (ret < 0) {
        mldebug("failed uv_udp_recv_stop(): %s", uv_strerror(ret));
    }

    uv_close((uv_handle_t*)qry->handle, _close_query_udp_cb);
}

static int _create_query_udp(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();

    int ret;
    _output_dnssim_query_udp_t* qry;
    core_object_payload_t* payload = (core_object_payload_t*)req->dns_q->obj_prev;

    lfatal_oom(qry = calloc(1, sizeof(_output_dnssim_query_udp_t)));
    lfatal_oom(qry->handle = malloc(sizeof(uv_udp_t)));

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_UDP;
    qry->qry.req = req;
    qry->buf = uv_buf_init((char*)payload->payload, payload->len);
    ret = uv_udp_init(&_self->loop, qry->handle);
    if (ret < 0) {
        lwarning("failed to init uv_udp_t");
        goto failure;
    }
    qry->handle->data = (void*)qry;
    _ll_append(req->qry, &qry->qry);

    // bind to IP address
    if (_self->source != NULL) {
        ret = uv_udp_bind(qry->handle, (struct sockaddr*)&_self->source->addr, 0);
        if (ret < 0) {
            lwarning("failed to bind to address: %s", uv_strerror(ret));
            return ret;
        }
        _self->source = _self->source->next;
    }

    ret = uv_udp_try_send(qry->handle, &qry->buf, 1, (struct sockaddr*)&_self->target);
    if (ret < 0) {
        lwarning("failed to send udp packet: %s", uv_strerror(ret));
        return ret;
    }

    // TODO IPv4
    struct sockaddr_in6 src;
    int addr_len = sizeof(src);
    uv_udp_getsockname(qry->handle, (struct sockaddr*)&src, &addr_len);
    ldebug("sent udp from port: %d", ntohs(src.sin6_port));

    // listen for reply
    ret = uv_udp_recv_start(qry->handle, _uv_alloc_cb, _query_udp_recv_cb);
    if (ret < 0) {
        lwarning("failed uv_udp_recv_start(): %s", uv_strerror(ret));
        return ret;
    }

    return 0;
failure:
    free(qry->handle);
    free(qry);
    return ret;
}

static void _create_request_udp(output_dnssim_t* self, _output_dnssim_client_t* client,
    core_object_payload_t* payload)
{
    mlassert_self();

    int ret;
    _output_dnssim_request_t* req;

    lfatal_oom(req = malloc(sizeof(_output_dnssim_request_t)));
    memset(req, 0, sizeof(_output_dnssim_request_t));
    req->dnssim = self;
    req->client = client;
    req->payload = payload;
    req->dns_q = core_object_dns_new();
    req->dns_q->obj_prev = (core_object_t*)req->payload;
    req->ongoing = 1;
    req->dnssim->ongoing++;

    ret = core_object_dns_parse_header(req->dns_q);
    if (ret != 0) {
        ldebug("discarded malformed dns query: couldn't parse header");
        goto failure;
    }

    req->dnssim->stats_sum->requests++;
    req->dnssim->stats_current->requests++;

    ret = _create_query_udp(self, req);
    if (ret < 0) {
        goto failure;
    }

    req->created_at = uv_now(&_self->loop);
    req->ended_at = req->created_at + self->timeout_ms;
    lfatal_oom(req->timeout = malloc(sizeof(uv_timer_t)));
    ret = uv_timer_init(&_self->loop, req->timeout);
    req->timeout->data = req;
    if (ret < 0) {
        ldebug("failed uv_timer_init(): %s", uv_strerror(ret));
        free(req->timeout);
        req->timeout = NULL;
        goto failure;
    }
    ret = uv_timer_start(req->timeout, _close_request_timeout, self->timeout_ms, 0);
    if (ret < 0) {
        ldebug("failed uv_timer_start(): %s", uv_strerror(ret));
        goto failure;
    }

    return;
failure:
    self->discarded++;
    _close_request(req);
    return;
}


/*
 * TCP dnssim
 *
 * TODO: extract functions common to tcp/udp into separate functions
 */
static void _write_tcp_query_cb(uv_write_t* req, int status)
{
    _output_dnssim_query_tcp_t* qry = (_output_dnssim_query_tcp_t*)req->data;

    if (status < 0) {  // TODO: handle more gracefully?
        qry->qry.state = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE;
        mlwarning("tcp write failed: %s", uv_strerror(status));
        // TODO: check if connection is writable, then check state.
        // if state == active, close the connection
        // this is called when conn is closed with uv_close() and there are peding write reqs
        return;
    }

    /* Mark query as sent and assign it to connection. */
    mlassert(qry->conn, "qry must be associated with connection");
    qry->qry.state = _OUTPUT_DNSSIM_QUERY_SENT;

    mlassert(qry->conn->queued, "conn has no queued queries");
    _ll_remove(qry->conn->queued, &qry->qry);
    _ll_append(qry->conn->sent, &qry->qry);

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

    qry->write_req.data = (void*)qry;
    uv_write(&qry->write_req, (uv_stream_t*)&conn->handle, qry->bufs, 2, _write_tcp_query_cb);
    qry->qry.state = _OUTPUT_DNSSIM_QUERY_PENDING_WRITE_CB;
}

static void _send_pending_queries(_output_dnssim_connection_t* conn)
{
    _output_dnssim_query_tcp_t* qry = (_output_dnssim_query_tcp_t*)conn->client->pending;

    while (qry != NULL) {
        mlassert(qry->qry.state == _OUTPUT_DNSSIM_QUERY_PENDING_WRITE, "query isn't in PENDING_WRITE state");
        _output_dnssim_query_tcp_t* next = (_output_dnssim_query_tcp_t*)qry->qry.next;
        _write_tcp_query(qry, conn);
        qry = next;
    }
}

void _process_tcp_dnsmsg(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");

    core_object_payload_t payload = CORE_OBJECT_PAYLOAD_INIT(NULL);
    core_object_dns_t dns_a = CORE_OBJECT_DNS_INIT(&payload);
    _output_dnssim_request_t* req;

    payload.payload = conn->recv_data;
    payload.len = conn->recv_len;

    dns_a.obj_prev = (core_object_t*)&payload;
    int ret = core_object_dns_parse_header(&dns_a);
    if (ret != 0) {
        mlwarning("dnsmsg malformed");
        return;
    }
    mldebug("tcp recv dnsmsg id: %04x", dns_a.id);

    // TODO consider using _output_dnssim_query_t
    _output_dnssim_query_tcp_t* qry = (_output_dnssim_query_tcp_t*)conn->sent;
    while (qry != NULL) {
        req = qry->qry.req;
        if (req->dns_q->id == dns_a.id) {
            _request_answered(req, &dns_a);
            _ll_remove(conn->sent, &qry->qry);
            _close_request(req);  // TODO might need more polishing to ensure free works
            break;
        }
        qry = (_output_dnssim_query_tcp_t*)qry->qry.next;
    }
}

void _parse_recv_data(_output_dnssim_connection_t* conn)
{
    mlassert(conn, "conn can't be nil");
    mlassert(conn->recv_pos == conn->recv_len, "attempt to parse incomplete dnslen");

    switch(conn->read_state) {
    case _OUTPUT_DNSSIM_READ_STATE_CLEAN:
        return;
    case _OUTPUT_DNSSIM_READ_STATE_DNSLEN: {
        uint16_t* p_dnslen = (uint16_t*)conn->recv_data;
        conn->recv_len = ntohs(*p_dnslen);
        mldebug("tcp dnslen: %d", conn->recv_len);
        conn->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSMSG;
        break;
    }
    case _OUTPUT_DNSSIM_READ_STATE_DNSMSG:
        _process_tcp_dnsmsg(conn);
        conn->recv_len = 0;
        conn->read_state = _OUTPUT_DNSSIM_READ_STATE_CLEAN;
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
}

size_t _handle_conn_data(_output_dnssim_connection_t* conn, char* data, size_t len)
{
    mlassert(conn, "conn can't be nil");
    mlassert(data, "data can't be nil");
    mlassert(len > 0, "data can't be nil");

    size_t expected = conn->recv_len - conn->recv_pos;
    mlassert(expected > 0, "no data expected");

    if (expected > len || conn->recv_free_after_use) {
        if (conn->recv_pos == 0) {
            mlassert(conn->recv_len > 0, "conn->recv_len must be set");
            mlassert(!conn->recv_free_after_use, "conn->recv_free_after_use shouldn't be set when pos=0");
            mlfatal_oom(conn->recv_data = malloc(conn->recv_len * sizeof(char)));
            conn->recv_free_after_use = true;
        }
        char* dest = conn->recv_data + conn->recv_pos;
        memcpy(dest, data, len);
        conn->recv_pos += len;
        return len;
    } else {
        conn->recv_data = data;
        conn->recv_pos = conn->recv_len;
        return expected;
    }
}

unsigned int _read_stream_data(_output_dnssim_connection_t* conn, size_t pos, const uv_buf_t* buf)
{
    mlassert(conn, "conn can't be nil");
    mlassert(buf, "buf can't be nil");
    mlassert(buf->len >= pos, "invalid position");
    mlassert(conn->read_state != _OUTPUT_DNSSIM_READ_STATE_INVALID, "connection has invalid read_state");

    char* data = buf->base + pos;
    size_t available = buf->len - pos;

    if (available == 0)
        return pos;

    if (conn->read_state == _OUTPUT_DNSSIM_READ_STATE_CLEAN) {
        conn->recv_len = 2;
        conn->recv_pos = 0;
        conn->recv_free_after_use = false;
        conn->read_state = _OUTPUT_DNSSIM_READ_STATE_DNSLEN;
    }

    pos += _handle_conn_data(conn, data, available);

    if (conn->recv_len == conn->recv_pos)
        _parse_recv_data(conn);

    return pos;
}

static void _close_tcp_connection_cb(uv_handle_t* handle)
{
    // TODO free unneeded, fail/reassign queries (+timers)
    // _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
}

static void _tcp_read_cb(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)handle->data;
    if (nread > 0) {
        int pos = 0;
        while (pos < nread)
            pos = _read_stream_data(conn, pos, buf);
        mlassert(pos == nread, "tcp data read invalid, pos != nread");
    } else if (nread < 0) {
        if (nread != UV_EOF)
            mlwarning("tcp conn unexpected close: %s", uv_strerror(nread));
        _ll_remove(conn->client->conn, conn);
        uv_close((uv_handle_t*)handle, _close_tcp_connection_cb);
    }

    if (buf->base != NULL)
        free(buf->base);
}

static void _connect_tcp_cb(uv_connect_t* conn_req, int status)
{
    _output_dnssim_connection_t* conn = (_output_dnssim_connection_t*)conn_req->handle->data;
    mlassert(conn->state == _OUTPUT_DNSSIM_CONN_CONNECTING, "connection state != CONNECTING");

    if (status < 0) {
        // TODO: handle this the same way as UDP retransmit - attempt reconnect after a period of time
        mlwarning("tcp connect failed: %s", uv_strerror(status));
        // TODO: close and remove handle
        return;
    }

    int ret = uv_read_start((uv_stream_t*)&conn->handle, _uv_alloc_cb, _tcp_read_cb);
    if (ret < 0) {
        // TODO: handle this
        mlwarning("tcp uv_read_start() failed: %s", uv_strerror(ret));
        return;
    }

    conn->state = _OUTPUT_DNSSIM_CONN_ACTIVE;
    conn->read_state = _OUTPUT_DNSSIM_READ_STATE_CLEAN;
    _send_pending_queries(conn);
}

static void _create_tcp_connection(output_dnssim_t* self, _output_dnssim_connection_t* conn)
{
    mlassert_self();
    lassert(conn, "connection can't be null");
    lassert(conn->state == _OUTPUT_DNSSIM_CONN_INITIALIZED, "connection state != INITIALIZED");

    uv_tcp_init(&_self->loop, &conn->handle);
    conn->handle.data = (void*)conn;

    /* Bind before connect to be able to send from different source IPs. */
    if (_self->source != NULL) {
        int ret = uv_tcp_bind(&conn->handle, (struct sockaddr*)&_self->source->addr, 0);
        if (ret < 0) {
            lwarning("failed to bind to address: %s", uv_strerror(ret));
            return;
        }
        _self->source = _self->source->next;
    }

    /* Set connection parameters. */
    int ret;
    ret = uv_tcp_nodelay(&conn->handle, 1);
    if (ret < 0)
        lwarning("tcp: failed to set TCP_NODELAY: %s", uv_strerror(ret));

    // TODO: make this configurable
    // ret = uv_tcp_keepalive(&conn->handle, 1, 5);
    // if (ret < 0)
    //     mlwarning("tcp: failed to set TCP_KEEPALIVE: %s", uv_strerror(ret));

    uv_tcp_connect(&conn->conn_req, &conn->handle, (struct sockaddr*)&_self->target, _connect_tcp_cb);
    conn->state = _OUTPUT_DNSSIM_CONN_CONNECTING;
}

static int _create_query_tcp(output_dnssim_t* self, _output_dnssim_request_t* req)
{
    mlassert_self();
    lassert(req->client, "request must have a client associated with it");

    int ret;
    _output_dnssim_query_tcp_t* qry;
    _output_dnssim_connection_t* conn;
    core_object_payload_t* payload = (core_object_payload_t*)req->dns_q->obj_prev;

    lfatal_oom(qry = calloc(1, sizeof(_output_dnssim_query_tcp_t)));  // TODO free

    qry->qry.transport = OUTPUT_DNSSIM_TRANSPORT_TCP;
    qry->qry.req = req;
    _ll_append(req->qry, &qry->qry);
    _ll_append(req->client->pending, &qry->qry);

    /* Get active TCP connection or find out whether new connection has to be opened. */
    bool is_connecting = false;
    conn = req->client->conn;
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
        lfatal_oom(conn = calloc(1, sizeof(_output_dnssim_connection_t)));  // TODO free
        conn->state = _OUTPUT_DNSSIM_CONN_INITIALIZED;
        conn->client = req->client;
        _create_tcp_connection(self, conn);  // TODO add exit code, possible failure?
        _ll_append(req->client->conn, conn);
    } /* Otherwise, pending queries wil be sent after connected callback. */

    return 0;  // TODO: any error states to handle?
}

static void _create_request_tcp(output_dnssim_t* self, _output_dnssim_client_t* client,
    core_object_payload_t* payload)
{
    mlassert_self();

    int ret;
    _output_dnssim_request_t* req;

    lfatal_oom(req = malloc(sizeof(_output_dnssim_request_t)));
    memset(req, 0, sizeof(_output_dnssim_request_t));
    req->dnssim = self;
    req->client = client;
    req->payload = payload;
    req->dns_q = core_object_dns_new();
    req->dns_q->obj_prev = (core_object_t*)req->payload;
    req->ongoing = 1;
    req->dnssim->ongoing++;

    ret = core_object_dns_parse_header(req->dns_q);
    if (ret != 0) {
        ldebug("discarded malformed dns query: couldn't parse header");
        goto failure;
    }

    req->dnssim->stats_sum->requests++;
    req->dnssim->stats_current->requests++;

    ret = _create_query_tcp(self, req);
    if (ret < 0) {
        goto failure;
    }

    lfatal_oom(req->timeout = malloc(sizeof(uv_timer_t)));
    ret = uv_timer_init(&_self->loop, req->timeout);
    req->timeout->data = req;
    if (ret < 0) {
        ldebug("failed uv_timer_init(): %s", uv_strerror(ret));
        free(req->timeout);
        req->timeout = NULL;
        goto failure;
    }
    ret = uv_timer_start(req->timeout, _close_request_timeout, self->timeout_ms, 0);
    if (ret < 0) {
        ldebug("failed uv_timer_start(): %s", uv_strerror(ret));
        goto failure;
    }

    return;
failure:
    self->discarded++;
    _close_request(req);
    return;
}

static void _close_query_tcp(_output_dnssim_query_tcp_t* qry)
{
    mlassert(qry, "qry can't be null");
    mlassert(qry->conn, "query must have associated connection");

    _ll_try_remove(qry->conn->queued, &qry->qry);
    _ll_try_remove(qry->conn->sent, &qry->qry);
}


/*** dnssim functions ***/
output_dnssim_t* output_dnssim_new(size_t max_clients)
{
    output_dnssim_t* self;
    int ret;

    mlfatal_oom(self = malloc(sizeof(_output_dnssim_t)));
    *self = _defaults;

    lfatal_oom(self->stats_sum = malloc(sizeof(output_dnssim_stats_t)));
    *self->stats_sum = _stats_defaults;
    lfatal_oom(self->stats_sum->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    lfatal_oom(self->stats_current = malloc(sizeof(output_dnssim_stats_t)));
    *self->stats_current = _stats_defaults;
    lfatal_oom(self->stats_current->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    self->stats_first = self->stats_current;

    _self->source = NULL;
    _self->transport = OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY;
    _self->create_request = _create_request_udp;

    lfatal_oom(_self->client_arr = calloc(
        max_clients, sizeof(_output_dnssim_client_t)));
    self->max_clients = max_clients;

    ret = uv_loop_init(&_self->loop);
    if (ret < 0) {
        lfatal("failed to initialize uv_loop (%s)", uv_strerror(ret));
    }
    ldebug("initialized uv_loop");

    return self;
}

void output_dnssim_free(output_dnssim_t* self)
{
    mlassert_self();
    int ret;
    _output_dnssim_source_t* source;
    _output_dnssim_source_t* first = _self->source;
    output_dnssim_stats_t* stats_prev;

    free(self->stats_sum->latency);
    free(self->stats_sum);
    do {
        stats_prev = self->stats_current->prev;
        free(self->stats_current->latency);
        free(self->stats_current);
        self->stats_current = stats_prev;
    } while (self->stats_current != NULL);

    if (_self->source != NULL) {
        // free cilcular linked list
        do {
            source = _self->source->next;
            free(_self->source);
            _self->source = source;
        } while (_self->source != first);
    }

    free(_self->client_arr);

    ret = uv_loop_close(&_self->loop);
    if (ret < 0) {  // TODO wait for TCP connections to close
        lcritical("failed to close uv_loop (%s)", uv_strerror(ret));
    } else {
        ldebug("closed uv_loop");
    }

    free(self);
}

uint32_t _extract_client(const core_object_t* obj) {
    uint32_t client;
    uint8_t* ip;

    switch (obj->obj_type) {
    case CORE_OBJECT_IP:
        ip = ((core_object_ip_t*)obj)->dst;
        break;
    case CORE_OBJECT_IP6:
        ip = ((core_object_ip6_t*)obj)->dst;
        break;
    default:
        return -1;
    }

    memcpy(&client, ip, sizeof(client));
    return client;
}

static void _receive(output_dnssim_t* self, const core_object_t* obj)
{
    mlassert_self();
    core_object_t* current = (core_object_t*)obj;
    core_object_payload_t* payload;
    uint32_t client;

    self->processed++;

    /* get payload from packet */
    for (;;) {
        if (current->obj_type == CORE_OBJECT_PAYLOAD) {
            payload = (core_object_payload_t*)current;
            break;
        }
        if (current->obj_prev == NULL) {
            self->discarded++;
            lwarning("packet discarded (missing payload object)");
            return;
        }
        current = (core_object_t*)current->obj_prev;
    }

    /* extract client information from IP/IP6 layer */
    for (;;) {
        if (current->obj_type == CORE_OBJECT_IP || current->obj_type == CORE_OBJECT_IP6) {
            client = _extract_client(current);
            break;
        }
        if (current->obj_prev == NULL) {
            self->discarded++;
            lwarning("packet discarded (missing ip/ip6 object)");
            return;
        }
        current = (core_object_t*)current->obj_prev;
    }

    if (self->free_after_use) {
        /* free all objects except payload */
        current = (core_object_t*)obj;
        core_object_t* parent = current;
        while (current != NULL) {
            parent = current;
            current = (core_object_t*)current->obj_prev;
            if (parent->obj_type != CORE_OBJECT_PAYLOAD) {
                core_object_free(parent);
            }
        }
    }

    if (client >= self->max_clients) {
        self->discarded++;
        lwarning("packet discarded (client exceeded max_clients)");
        return;
    }

    ldebug("client(c): %d", client);
    _self->create_request(self, &_self->client_arr[client], payload);
}

core_receiver_t output_dnssim_receiver()
{
    return (core_receiver_t)_receive;
}

void output_dnssim_set_transport(output_dnssim_t* self, output_dnssim_transport_t tr) {
    mlassert_self();

    switch(tr) {
    case OUTPUT_DNSSIM_TRANSPORT_UDP_ONLY:
        _self->create_request = _create_request_udp;
        lnotice("transport set to UDP (no TCP fallback)");
        break;
    case OUTPUT_DNSSIM_TRANSPORT_TCP:
        _self->create_request = _create_request_tcp;
        lnotice("transport set to TCP");
        break;
    case OUTPUT_DNSSIM_TRANSPORT_UDP:
    case OUTPUT_DNSSIM_TRANSPORT_TLS:
    default:
        lfatal("unknown or unsupported transport");
        break;
    }

    _self->transport = tr;
}

int output_dnssim_target(output_dnssim_t* self, const char* ip, uint16_t port) {
    int ret;
    mlassert_self();
    lassert(ip, "ip is nil");
    lassert(port, "port is nil");

    ret = uv_ip6_addr(ip, port, (struct sockaddr_in6*)&_self->target);
    if (ret != 0) {
        lcritical("failed to parse IPv6 from \"%s\"", ip);
        return -1;
        // TODO IPv4 support
        //ret = uv_ip4_addr(ip, port, (struct sockaddr_in*)&_self->target);
        //if (ret != 0) {
        //    lcritical("failed to parse IP/IP6 from \"%s\"", ip);
        //    return -1;
        //}
    }

    lnotice("set target to %s port %d", ip, port);
    return 0;
}

int output_dnssim_bind(output_dnssim_t* self, const char* ip) {
    int ret;
    mlassert_self();
    lassert(ip, "ip is nil");

    _output_dnssim_source_t* source;
    lfatal_oom(source = malloc(sizeof(_output_dnssim_source_t)));

    ret = uv_ip6_addr(ip, 0, (struct sockaddr_in6*)&source->addr);
    if (ret != 0) {
        lfatal("failed to parse IPv6 from \"%s\"", ip);
        return -1;
        // TODO IPv4 support
    }

    if (_self->source == NULL) {
        source->next = source;
        _self->source = source;
    } else {
        source->next = _self->source->next;
        _self->source->next = source;
    }

    lnotice("bind to source address %s", ip);
    return 0;
}

int output_dnssim_run_nowait(output_dnssim_t* self)
{
    mlassert_self();

    return uv_run(&_self->loop, UV_RUN_NOWAIT);
}

static void _stats_timer_cb(uv_timer_t* handle)
{
    uint64_t now_ms = _now_ms();
    output_dnssim_t* self = (output_dnssim_t*)handle->data;
    lnotice("total processed:%10ld; answers:%10ld; discarded:%10ld; ongoing:%10ld",
        self->processed, self->stats_sum->answers, self->discarded,
        self->ongoing);

    output_dnssim_stats_t* stats_next;
    lfatal_oom(stats_next = malloc(sizeof(output_dnssim_stats_t)));
    *stats_next = _stats_defaults;
    lfatal_oom(stats_next->latency = calloc(self->timeout_ms + 1, sizeof(uint64_t)));

    self->stats_current->until_ms = now_ms;
    stats_next->since_ms = now_ms;

    stats_next->ongoing = self->ongoing;
    stats_next->prev = self->stats_current;
    self->stats_current->next = stats_next;
    self->stats_current = stats_next;
}

void output_dnssim_stats_collect(output_dnssim_t* self, uint64_t interval_ms)
{
    int ret;
    uint64_t now_ms = _now_ms();
    mlassert_self();

    if (self->stats_interval_ms != 0) {
        lfatal("statistics collection has already started!");
    }
    self->stats_interval_ms = interval_ms;

    self->stats_sum->since_ms = now_ms;
    self->stats_current->since_ms = now_ms;

    _self->stats_timer.data = (void*)self;
    ret = uv_timer_init(&_self->loop, &_self->stats_timer);
    if (ret < 0) {
        lcritical("failed to init stats_timer: %s", uv_strerror(ret));
        return;
    }
    ret = uv_timer_start(&_self->stats_timer, _stats_timer_cb, interval_ms, interval_ms);
    if (ret < 0) {
        lcritical("failed to start stats_timer: %s", uv_strerror(ret));
        return;
    }
}

void output_dnssim_stats_finish(output_dnssim_t* self)
{
    int ret;
    uint64_t now_ms = _now_ms();
    mlassert_self();

    self->stats_sum->until_ms = now_ms;
    self->stats_current->until_ms = now_ms;

    ret = uv_timer_stop(&_self->stats_timer);
    if (ret < 0) {
        lcritical("failed to stop stats_timer: %s", uv_strerror(ret));
        return;
    }
    uv_close((uv_handle_t*)&_self->stats_timer, NULL);
}

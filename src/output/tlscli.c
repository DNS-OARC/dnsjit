/*
 * Copyright (c) 2018, OARC, Inc.
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

#include "output/tlscli.h"
#include "core/assert.h"
#include "core/object/dns.h"
#include "core/object/payload.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <poll.h>

static core_log_t      _log      = LOG_T_INIT("output.tlscli");
static output_tlscli_t _defaults = {
    LOG_T_INIT_OBJ("output.tlscli"),
    0, 0, -1, 0,
    { 0 }, CORE_OBJECT_PAYLOAD_INIT(0),
    0, 0, 0, 0,
    { 5, 0 },
    0, 0
};

core_log_t* output_tlscli_log()
{
    return &_log;
}

void output_tlscli_init(output_tlscli_t* self)
{
    int err;
    mlassert_self();

    *self             = _defaults;
    self->pkt.payload = self->recvbuf;

    gnutls_global_init();
    if ((err = gnutls_certificate_allocate_credentials(&self->cred)) != GNUTLS_E_SUCCESS) {
        lfatal("gnutls_certificate_allocate_credentials() error: %s", gnutls_strerror(err));
    } else if ((err = gnutls_init(&self->session, GNUTLS_CLIENT)) != GNUTLS_E_SUCCESS) {
        lfatal("gnutls_init() error: %s", gnutls_strerror(err));
    } else if ((err = gnutls_set_default_priority(self->session)) != GNUTLS_E_SUCCESS) {
        lfatal("gnutls_set_default_priority() error: %s", gnutls_strerror(err));
    } else if ((err = gnutls_credentials_set(self->session, GNUTLS_CRD_CERTIFICATE, self->cred)) != GNUTLS_E_SUCCESS) {
        lfatal("gnutls_credentials_set() error: %s", gnutls_strerror(err));
    }

    gnutls_handshake_set_timeout(self->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
}

void output_tlscli_destroy(output_tlscli_t* self)
{
    mlassert_self();

    if (self->fd > -1) {
        if (self->session) {
            gnutls_bye(self->session, GNUTLS_SHUT_RDWR);
            gnutls_deinit(self->session);
        }
        shutdown(self->fd, SHUT_RDWR);
        close(self->fd);
        if (self->cred) {
            gnutls_certificate_free_credentials(self->cred);
        }
    }
}

int output_tlscli_connect(output_tlscli_t* self, const char* host, const char* port)
{
    struct addrinfo* addr;
    int              err;
    unsigned int     ms;
    mlassert_self();
    lassert(host, "host is nil");
    lassert(port, "port is nil");

    if (self->fd > -1) {
        lfatal("already connected");
    }
    if (self->tls_ok) {
        lfatal("TLS already established");
    }

    if ((err = getaddrinfo(host, port, 0, &addr))) {
        lcritical("getaddrinfo(%s, %s) error %s", host, port, gai_strerror(err));
        return -1;
    }
    if (!addr) {
        lcritical("getaddrinfo failed, no address returned");
        return -1;
    }

    if ((self->fd = socket(addr->ai_addr->sa_family, SOCK_STREAM, 0)) < 0) {
        lcritical("socket() error %s", core_log_errstr(errno));
        freeaddrinfo(addr);
        return -2;
    }

    if (connect(self->fd, addr->ai_addr, addr->ai_addrlen)) {
        lcritical("connect() error %s", core_log_errstr(errno));
        freeaddrinfo(addr);
        return -2;
    }

    freeaddrinfo(addr);

    gnutls_transport_set_int(self->session, self->fd);
    ms = (self->timeout.sec * 1000) + (self->timeout.nsec / 1000000);
    if (!ms && self->timeout.nsec) {
        ms = 1;
    }
    gnutls_record_set_timeout(self->session, ms);

    /* Establish TLS */
    do {
        err = gnutls_handshake(self->session);
    } while (err < 0 && gnutls_error_is_fatal(err) == 0);
    if (err == GNUTLS_E_PREMATURE_TERMINATION) {
        lcritical("gnutls_handshake() error: %s", gnutls_strerror(err));
        return -3;
    } else if (err < 0) {
        lcritical("gnutls_handshake() failed: %s (%d)\n", gnutls_strerror(err), err);
        return -3;
    }

    self->tls_ok = 1;
    return 0;
}

static void _receive(output_tlscli_t* self, const core_object_t* obj)
{
    const uint8_t* payload;
    size_t         len, sent;
    uint16_t       dnslen;
    ssize_t        ret;
    mlassert_self();

    for (; obj;) {
        switch (obj->obj_type) {
        case CORE_OBJECT_DNS:
            obj = obj->obj_prev;
            continue;
        case CORE_OBJECT_PAYLOAD:
            payload = ((core_object_payload_t*)obj)->payload;
            len     = ((core_object_payload_t*)obj)->len;
            break;
        default:
            return;
        }

        sent   = 0;
        dnslen = htons(len);

        for (;;) {
            ret = gnutls_record_send(self->session, ((uint8_t*)&dnslen) + sent, sizeof(dnslen) - sent);
            if (ret > -1) {
                sent += ret;
                if (sent < sizeof(dnslen))
                    continue;

                sent = 0;
                for (;;) {
                    ret = gnutls_record_send(self->session, payload + sent, len - sent);
                    if (ret > -1) {
                        sent += ret;
                        if (sent < len)
                            continue;
                        self->pkts++;
                        return;
                    }
                    switch (ret) {
                    case GNUTLS_E_AGAIN:
                    case GNUTLS_E_INTERRUPTED:
                        continue;
                    default:
                        break;
                    }
                    break;
                }
                self->errs++;
                return;
            }
            switch (ret) {
            case GNUTLS_E_AGAIN:
            case GNUTLS_E_INTERRUPTED:
                continue;
            default:
                break;
            }
            break;
        }
        self->errs++;
        break;
    }
}

core_receiver_t output_tlscli_receiver(output_tlscli_t* self)
{
    mlassert_self();

    if (self->fd < 0) {
        lfatal("not connected");
    }
    if (!self->tls_ok) {
        lfatal("TLS is not established");
    }

    return (core_receiver_t)_receive;
}

static const core_object_t* _produce(output_tlscli_t* self)
{
    ssize_t  n, recv = 0;
    uint16_t dnslen;
    mlassert_self();

    // Check if last recvfrom() got more then we needed
    if (!self->have_dnslen && self->recv > self->dnslen) {
        recv = self->recv - self->dnslen;
        if (recv < sizeof(dnslen)) {
            memcpy(((uint8_t*)&dnslen), self->recvbuf + self->dnslen, recv);
        } else {
            memcpy(((uint8_t*)&dnslen), self->recvbuf + self->dnslen, sizeof(dnslen));

            if (recv > sizeof(dnslen)) {
                self->recv = recv - sizeof(dnslen);
                memmove(self->recvbuf, self->recvbuf + self->dnslen + sizeof(dnslen), self->recv);
            } else {
                self->recv = 0;
            }

            self->dnslen      = ntohs(dnslen);
            self->have_dnslen = 1;

            if (self->recv > self->dnslen) {
                self->pkts_recv++;
                self->pkt.len     = self->dnslen;
                self->have_dnslen = 0;
                return (core_object_t*)&self->pkt;
            }
        }
    }

    if (!self->have_dnslen) {
        for (;;) {
            n = gnutls_record_recv(self->session, ((uint8_t*)&dnslen) + recv, sizeof(dnslen) - recv);
            if (n > 0) {
                recv += n;
                if (recv < sizeof(dnslen))
                    continue;
                break;
            }
            if (!n) {
                break;
            }
            switch (n) {
            case GNUTLS_E_AGAIN:
            case GNUTLS_E_INTERRUPTED:
                self->pkt.len = 0;
                return (core_object_t*)&self->pkt;
            default:
                break;
            }
            self->errs++;
            break;
        }

        if (n < 1) {
            return 0;
        }

        self->dnslen      = ntohs(dnslen);
        self->have_dnslen = 1;
        self->recv        = 0;
    }

    for (;;) {
        n = gnutls_record_recv(self->session, self->recvbuf + self->recv, sizeof(self->recvbuf) - self->recv);
        if (n > 0) {
            self->recv += n;
            if (self->recv < self->dnslen)
                continue;
            break;
        }
        if (!n) {
            break;
        }
        switch (n) {
        case GNUTLS_E_AGAIN:
        case GNUTLS_E_INTERRUPTED:
            self->pkt.len = 0;
            return (core_object_t*)&self->pkt;
        default:
            break;
        }
        self->errs++;
        break;
    }

    if (n < 1) {
        return 0;
    }

    self->pkts_recv++;
    self->pkt.len     = self->dnslen;
    self->have_dnslen = 0;
    return (core_object_t*)&self->pkt;
}

core_producer_t output_tlscli_producer(output_tlscli_t* self)
{
    mlassert_self();

    if (self->fd < 0) {
        lfatal("not connected");
    }
    if (!self->tls_ok) {
        lfatal("TLS is not established");
    }

    return (core_producer_t)_produce;
}

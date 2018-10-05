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
#include <gnutls/gnutls.h>

static core_log_t      _log      = LOG_T_INIT("output.tlscli");
static output_tlscli_t _defaults = {
    LOG_T_INIT_OBJ("output.tlscli"),
    0, 0, -1,
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
    mlassert_self();

    *self             = _defaults;
    self->pkt.payload = self->recvbuf;
}

void output_tlscli_destroy(output_tlscli_t* self)
{
    mlassert_self();

    if (self->fd > -1) {
        gnutls_bye(self->session, GNUTLS_SHUT_RDWR);
        shutdown(self->fd, SHUT_RDWR);
        close(self->fd);
        gnutls_deinit(self->session);
        gnutls_certificate_free_credentials(self->cred);
    }
}

int output_tlscli_connect(output_tlscli_t* self, const char* host, const char* port)
{
    struct addrinfo* addr;
    int              err;
    ssize_t          ret;
    mlassert_self();
    lassert(host, "host is nil");
    lassert(port, "port is nil");

    if (self->fd > -1) {
        lfatal("already connected");
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

    /* Establish TLS */
    if ((ret = gnutls_certificate_allocate_credentials(&self->cred)) < 0) {
        lcritical("gnutls error: %s", gnutls_strerror(ret));
        return -3;
    }

    if ((ret = gnutls_init(&self->session, GNUTLS_CLIENT)) < 0) {
        lcritical("gnutls error: %s", gnutls_strerror(ret));
        gnutls_certificate_free_credentials(self->cred);
        return -3;
    }

    if ((ret = gnutls_set_default_priority(self->session)) < 0) {
        lcritical("gnutls error: %s", gnutls_strerror(ret));
        gnutls_deinit(self->session);
        gnutls_certificate_free_credentials(self->cred);
        return -3;
    }

    if ((ret = gnutls_credentials_set(self->session, GNUTLS_CRD_CERTIFICATE, self->cred)) < 0) {
        lcritical("gnutls error: %s", gnutls_strerror(ret));
        gnutls_deinit(self->session);
        gnutls_certificate_free_credentials(self->cred);
        return -3;
    }

    gnutls_transport_set_int(self->session, self->fd);
    gnutls_handshake_set_timeout(self->session,
                                 GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    do {
            ret = gnutls_handshake(self->session);
    } while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
    if (ret == GNUTLS_E_PREMATURE_TERMINATION) {
        lcritical("gnutls error: %s", gnutls_strerror(ret));
        lcritical("Are you using the DNS-over-TLS port?");
        gnutls_deinit(self->session);
        gnutls_certificate_free_credentials(self->cred);
        return -3;
    }
    else if (ret < 0) {
        lcritical("TLS handshake failed: %s (%d)\n", gnutls_strerror(ret), ret);
        gnutls_deinit(self->session);
        gnutls_certificate_free_credentials(self->cred);
        return -3;
    }

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

    return (core_receiver_t)_receive;
}

static const core_object_t* _produce(output_tlscli_t* self)
{
    ssize_t       n, recv = 0;
    uint16_t      dnslen;
    struct pollfd p;
    int           to = 0;
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
                self->pkt.len = self->dnslen;
                self->have_dnslen = 0;
                return (core_object_t*)&self->pkt;
            }
        }
    }

    p.fd      = self->fd;
    p.events  = POLLIN;
    p.revents = 0;
    to        = (self->timeout.sec * 1e3) + (self->timeout.nsec / 1e6);
    if (!to) {
        to = 1;
    }

    if (!self->have_dnslen) {
        for (;;) {
            n = poll(&p, 1, to);
            if (n < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) {
                self->errs++;
                return 0;
            }
            if (!n || !(p.revents & POLLIN)) {
                if (recv) {
                    self->errs++;
                    return 0;
                }
                self->pkt.len = 0;
                return (core_object_t*)&self->pkt;
            }

            lassert(sizeof(dnslen) - recv >= 0, "sizeof(dnslen) - recv < 0");
            n = gnutls_record_recv(self->session, ((uint8_t*)&dnslen) + recv, sizeof(dnslen) - recv);
            ldebug("n: %d", n);
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
                continue;
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
        ldebug("dnslen: %d", self->dnslen);
        self->have_dnslen = 1;
        self->recv        = 0;
    }

    for (;;) {
        // TODO: add timeout support
        /*
        n = poll(&p, 1, to);
        if (n < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            self->errs++;
            return 0;
        }
        if (!n || !(p.revents & POLLIN)) {
            self->pkt.len = 0;
            return (core_object_t*)&self->pkt;
        }
        */

        n = gnutls_record_recv(self->session,self->recvbuf + self->recv, sizeof(self->recvbuf) - self->recv);
        ldebug("n2: %d", n);
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
    self->pkt.len = self->dnslen;
    self->have_dnslen = 0;
    return (core_object_t*)&self->pkt;
}

core_producer_t output_tlscli_producer(output_tlscli_t* self)
{
    mlassert_self();

    if (self->fd < 0) {
        lfatal("not connected");
    }

    return (core_producer_t)_produce;
}

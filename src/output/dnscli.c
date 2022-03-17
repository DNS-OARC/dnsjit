/*
 * Copyright (c) 2018-2021, OARC, Inc.
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

#include "output/dnscli.h"
#include "core/assert.h"
#include "core/object/dns.h"
#include "core/object/payload.h"
#include "core/object/udp.h"
#include "core/object/tcp.h"

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#else
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#else
#ifdef HAVE_MACHINE_ENDIAN_H
#include <machine/endian.h>
#endif
#endif
#endif
#ifdef HAVE_BYTESWAP_H
#include <byteswap.h>
#endif
#ifndef bswap_16
#ifndef bswap16
#define bswap_16(x) swap16(x)
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)
#else
#define bswap_16(x) bswap16(x)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#endif
#endif

static inline uint16_t _need16(const void* ptr)
{
    uint16_t v;
    memcpy(&v, ptr, sizeof(v));
    return be16toh(v);
}

static core_log_t      _log      = LOG_T_INIT("output.dnscli");
static output_dnscli_t _defaults = {
    LOG_T_INIT_OBJ("output.dnscli"),
    OUTPUT_DNSCLI_MODE_NONE,
    0, 0, 0, -1, 0, 0,
    { 0, 0, 0 }, 0,
    { 0 }, 0,
    { 0 }, CORE_OBJECT_PAYLOAD_INIT(0), 0, 0, 0, 0, 0,
    { 0, 0 },
    0, 0
};

core_log_t* output_dnscli_log()
{
    return &_log;
}

void output_dnscli_init(output_dnscli_t* self, output_dnscli_mode_t mode)
{
    mlassert_self();

    *self             = _defaults;
    self->mode        = mode;
    self->pkt.payload = self->recvbuf;

    switch (mode & OUTPUT_DNSCLI_MODE_MODES) {
    case OUTPUT_DNSCLI_MODE_UDP:
    case OUTPUT_DNSCLI_MODE_TCP:
        break;
    case OUTPUT_DNSCLI_MODE_TLS: {
        int err;
        if ((err = gnutls_certificate_allocate_credentials(&self->cred)) != GNUTLS_E_SUCCESS) {
            lfatal("gnutls_certificate_allocate_credentials() error: %s", gnutls_strerror(err));
        } else if ((err = gnutls_init(&self->session, GNUTLS_CLIENT | ((mode & OUTPUT_DNSCLI_MODE_NONBLOCKING) ? GNUTLS_NONBLOCK : 0))) != GNUTLS_E_SUCCESS) {
            lfatal("gnutls_init() error: %s", gnutls_strerror(err));
        } else if ((err = gnutls_set_default_priority(self->session)) != GNUTLS_E_SUCCESS) {
            lfatal("gnutls_set_default_priority() error: %s", gnutls_strerror(err));
        } else if ((err = gnutls_credentials_set(self->session, GNUTLS_CRD_CERTIFICATE, self->cred)) != GNUTLS_E_SUCCESS) {
            lfatal("gnutls_credentials_set() error: %s", gnutls_strerror(err));
        }

        gnutls_handshake_set_timeout(self->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
        break;
    }
    default:
        lfatal("Invalid mode %x", mode);
    }
}

void output_dnscli_destroy(output_dnscli_t* self)
{
    mlassert_self();

    if (self->fd > -1) {
        switch (self->mode & OUTPUT_DNSCLI_MODE_MODES) {
        case OUTPUT_DNSCLI_MODE_UDP:
        case OUTPUT_DNSCLI_MODE_TCP:
            shutdown(self->fd, SHUT_RDWR);
            close(self->fd);
            break;
        case OUTPUT_DNSCLI_MODE_TLS:
            if (self->session) {
                gnutls_bye(self->session, GNUTLS_SHUT_RDWR);
                gnutls_deinit(self->session);
            }
            shutdown(self->fd, SHUT_RDWR);
            close(self->fd);
            if (self->cred) {
                gnutls_certificate_free_credentials(self->cred);
            }
            break;
        default:
            break;
        }
    }
}

int output_dnscli_connect(output_dnscli_t* self, const char* host, const char* port)
{
    struct addrinfo* addr;
    int              err;
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

    switch (self->mode & OUTPUT_DNSCLI_MODE_MODES) {
    case OUTPUT_DNSCLI_MODE_UDP:
        memcpy(&self->addr, addr->ai_addr, addr->ai_addrlen);
        self->addr_len = addr->ai_addrlen;
        freeaddrinfo(addr);

        if ((self->fd = socket(((struct sockaddr*)&self->addr)->sa_family, SOCK_DGRAM, 0)) < 0) {
            lcritical("socket() error %s", core_log_errstr(errno));
            return -2;
        }
        break;
    case OUTPUT_DNSCLI_MODE_TCP:
    case OUTPUT_DNSCLI_MODE_TLS:
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
        break;
    default:
        break;
    }

    switch (self->mode & OUTPUT_DNSCLI_MODE_MODES) {
    case OUTPUT_DNSCLI_MODE_UDP:
    case OUTPUT_DNSCLI_MODE_TCP:
        if (self->mode & OUTPUT_DNSCLI_MODE_NONBLOCKING) {
            int flags;

            if ((flags = fcntl(self->fd, F_GETFL)) == -1) {
                lcritical("fcntl(FL_GETFL) error %s", core_log_errstr(errno));
                return -3;
            }

            if (fcntl(self->fd, F_SETFL, flags | O_NONBLOCK)) {
                lcritical("fcntl(FL_SETFL, %x) error %s", flags, core_log_errstr(errno));
                return -3;
            }
            self->nonblocking = 1;
        }
        if (self->timeout.sec > 0 || self->timeout.nsec > 0) {
            self->poll.fd      = self->fd;
            self->poll_timeout = (self->timeout.sec * 1e3) + (self->timeout.nsec / 1e6); //NOSONAR
            if (!self->poll_timeout) {
                self->poll_timeout = 1;
            }
        }
        break;
    case OUTPUT_DNSCLI_MODE_TLS: {
        unsigned int ms;
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
        break;
    }
    default:
        break;
    }

    self->conn_ok = 1;
    return 0;
}

static inline ssize_t _send_udp(output_dnscli_t* self, const uint8_t* payload, size_t len, size_t sent)
{
    ssize_t n;

    if (self->poll_timeout) {
        self->poll.events = POLLOUT;
        n                 = poll(&self->poll, 1, self->poll_timeout);
        if (n != 1 || !(self->poll.revents & POLLOUT)) {
            if (!n) {
                self->timeouts++;
                return -1;
            }
            self->errs++;
            return -2;
        }
    }
    n = sendto(self->fd, payload + sent, len - sent, 0, (struct sockaddr*)&self->addr, self->addr_len);
    if (n > -1) {
        return n;
    }
    switch (errno) {
    case EAGAIN:
#if EAGAIN != EWOULDBLOCK
    case EWOULDBLOCK:
#endif
    case EINTR:
        return -1;
    default:
        break;
    }
    return -2;
}

static void _receive_udp(output_dnscli_t* self, const core_object_t* obj)
{
    const uint8_t* payload;
    size_t         len, sent = 0;
    ssize_t        n;
    mlassert_self();

    switch (obj->obj_type) {
    case CORE_OBJECT_DNS:
        payload = ((core_object_dns_t*)obj)->payload;
        len     = ((core_object_dns_t*)obj)->len;

        if (((core_object_dns_t*)obj)->includes_dnslen) {
            if (len < 2) {
                return;
            }
            payload += 2;
            len -= 2;
        }
        break;
    case CORE_OBJECT_PAYLOAD:
        payload = ((core_object_payload_t*)obj)->payload;
        len     = ((core_object_payload_t*)obj)->len;
        break;
    default:
        return;
    }

    for (;;) {
        n = _send_udp(self, payload, len, sent);
        if (n > -1) {
            sent += n;
            if (sent < len) {
                continue;
            }
            self->pkts++;
            return;
        }
        if (n == -1) {
            if (self->nonblocking) {
                // TODO: warn?
                return;
            }
            continue;
        }
        break;
    }
    self->errs++;
}

static inline ssize_t _send_tcp(output_dnscli_t* self, const uint8_t* payload, size_t len, size_t sent)
{
    ssize_t n;

    if (self->poll_timeout) {
        self->poll.events = POLLOUT;
        n                 = poll(&self->poll, 1, self->poll_timeout);
        if (n != 1 || !(self->poll.revents & POLLOUT)) {
            if (!n) {
                self->timeouts++;
                return -1;
            }
            self->errs++;
            return -2;
        }
    }
    n = sendto(self->fd, payload + sent, len - sent, 0, 0, 0);
    if (n > -1) {
        return n;
    }
    switch (errno) {
    case EAGAIN:
#if EAGAIN != EWOULDBLOCK
    case EWOULDBLOCK:
#endif
    case EINTR:
        return -1;
    default:
        break;
    }
    return -2;
}

static void _receive_tcp(output_dnscli_t* self, const core_object_t* obj)
{
    const uint8_t* payload;
    size_t         len, sent = 0;
    ssize_t        n;
    mlassert_self();

    switch (obj->obj_type) {
    case CORE_OBJECT_DNS:
        if (!((core_object_dns_t*)obj)->includes_dnslen) {
            uint16_t dnslen = htons(((core_object_dns_t*)obj)->len);
            payload         = (const uint8_t*)&dnslen;
            len             = sizeof(dnslen);

            for (;;) {
                n = _send_tcp(self, payload, len, sent);
                if (n > -1) {
                    sent += n;
                    if (sent < len) {
                        continue;
                    }
                    break;
                }
                if (n == -1) {
                    if (self->nonblocking) {
                        // TODO: warn?
                        return;
                    }
                    continue;
                }
                self->errs++;
                return;
            }
            sent = 0;
        }
        payload = ((core_object_dns_t*)obj)->payload;
        len     = ((core_object_dns_t*)obj)->len;
        break;
    case CORE_OBJECT_PAYLOAD:
        payload = ((core_object_payload_t*)obj)->payload;
        len     = ((core_object_payload_t*)obj)->len;
        break;
    default:
        return;
    }

    for (;;) {
        n = _send_tcp(self, payload, len, sent);
        if (n > -1) {
            sent += n;
            if (sent < len) {
                continue;
            }
            self->pkts++;
            return;
        }
        if (n == -1) {
            if (self->nonblocking) {
                // TODO: warn?
                return;
            }
            continue;
        }
        break;
    }
    self->errs++;
}

static inline ssize_t _send_tls(output_dnscli_t* self, const uint8_t* payload, size_t len, size_t sent)
{
    ssize_t n;

    n = gnutls_record_send(self->session, payload + sent, len - sent);
    if (n > -1) {
        return n;
    }
    switch (n) {
    case GNUTLS_E_AGAIN:
    case GNUTLS_E_TIMEDOUT:
    case GNUTLS_E_INTERRUPTED:
        return -1;
    default:
        break;
    }
    return -2;
}

static void _receive_tls(output_dnscli_t* self, const core_object_t* obj)
{
    const uint8_t* payload;
    size_t         len, sent = 0;
    ssize_t        n;
    mlassert_self();

    switch (obj->obj_type) {
    case CORE_OBJECT_DNS:
        if (!((core_object_dns_t*)obj)->includes_dnslen) {
            uint16_t dnslen = htons(((core_object_dns_t*)obj)->len);
            payload         = (const uint8_t*)&dnslen;
            len             = sizeof(dnslen);

            for (;;) {
                n = _send_tls(self, payload, len, sent);
                if (n > -1) {
                    sent += n;
                    if (sent < len) {
                        continue;
                    }
                    break;
                }
                if (n == -1) {
                    if (self->nonblocking) {
                        // TODO: warn?
                        return;
                    }
                    continue;
                }
                self->errs++;
                return;
            }
            sent = 0;
        }
        payload = ((core_object_dns_t*)obj)->payload;
        len     = ((core_object_dns_t*)obj)->len;
        break;
    case CORE_OBJECT_PAYLOAD:
        payload = ((core_object_payload_t*)obj)->payload;
        len     = ((core_object_payload_t*)obj)->len;
        break;
    default:
        return;
    }

    for (;;) {
        n = _send_tls(self, payload, len, sent);
        if (n > -1) {
            sent += n;
            if (sent < len) {
                continue;
            }
            self->pkts++;
            return;
        }
        if (n == -1) {
            if (self->nonblocking) {
                // TODO: warn?
                return;
            }
            continue;
        }
        break;
    }
    self->errs++;
}

luajit_ssize_t output_dnscli_send(output_dnscli_t* self, const core_object_t* obj, size_t sent)
{
    const uint8_t* payload;
    size_t         len;
    uint16_t       dnslen;
    mlassert_self();

    switch (self->mode & OUTPUT_DNSCLI_MODE_MODES) {
    case OUTPUT_DNSCLI_MODE_UDP:
        switch (obj->obj_type) {
        case CORE_OBJECT_DNS:
            payload = ((core_object_dns_t*)obj)->payload;
            len     = ((core_object_dns_t*)obj)->len;

            if (((core_object_dns_t*)obj)->includes_dnslen) {
                if (len < 2) {
                    return -2;
                }
                payload += 2;
                len -= 2;
            }
            break;
        case CORE_OBJECT_PAYLOAD:
            payload = ((core_object_payload_t*)obj)->payload;
            len     = ((core_object_payload_t*)obj)->len;
            break;
        default:
            return -2;
        }

        return _send_udp(self, payload, len, sent);

    case OUTPUT_DNSCLI_MODE_TCP:
        switch (obj->obj_type) {
        case CORE_OBJECT_DNS:
            if (!((core_object_dns_t*)obj)->includes_dnslen) {
                if (sent < sizeof(dnslen)) {
                    dnslen  = htons(((core_object_dns_t*)obj)->len);
                    payload = (const uint8_t*)&dnslen;
                    len     = sizeof(dnslen);

                    return _send_tcp(self, payload, len, sent);
                }
                sent -= sizeof(dnslen);
            }
            payload = ((core_object_dns_t*)obj)->payload;
            len     = ((core_object_dns_t*)obj)->len;
            break;
        case CORE_OBJECT_PAYLOAD:
            payload = ((core_object_payload_t*)obj)->payload;
            len     = ((core_object_payload_t*)obj)->len;
            break;
        default:
            return -2;
        }

        return _send_tcp(self, payload, len, sent);

    case OUTPUT_DNSCLI_MODE_TLS:
        switch (obj->obj_type) {
        case CORE_OBJECT_DNS:
            if (!((core_object_dns_t*)obj)->includes_dnslen) {
                if (sent < sizeof(dnslen)) {
                    dnslen  = htons(((core_object_dns_t*)obj)->len);
                    payload = (const uint8_t*)&dnslen;
                    len     = sizeof(dnslen);

                    return _send_tls(self, payload, len, sent);
                }
                sent -= sizeof(dnslen);
            }
            payload = ((core_object_dns_t*)obj)->payload;
            len     = ((core_object_dns_t*)obj)->len;
            break;
        case CORE_OBJECT_PAYLOAD:
            payload = ((core_object_payload_t*)obj)->payload;
            len     = ((core_object_payload_t*)obj)->len;
            break;
        default:
            return -2;
        }

        return _send_tls(self, payload, len, sent);

    default:
        break;
    }

    return -2;
}

core_receiver_t output_dnscli_receiver(output_dnscli_t* self)
{
    mlassert_self();

    if (!self->conn_ok) {
        lfatal("not connected");
    }

    switch (self->mode & OUTPUT_DNSCLI_MODE_MODES) {
    case OUTPUT_DNSCLI_MODE_UDP:
        return (core_receiver_t)_receive_udp;
    case OUTPUT_DNSCLI_MODE_TCP:
        return (core_receiver_t)_receive_tcp;
    case OUTPUT_DNSCLI_MODE_TLS:
        return (core_receiver_t)_receive_tls;
    default:
        break;
    }

    lfatal("internal error");
    return 0;
}

static const core_object_t* _produce_udp(output_dnscli_t* self)
{
    ssize_t n;
    mlassert_self();

    for (;;) {
        if (self->poll_timeout) {
            self->poll.events = POLLIN;
            n                 = poll(&self->poll, 1, self->poll_timeout);
            if (n != 1 || !(self->poll.revents & POLLIN)) {
                if (!n) {
                    self->timeouts++;
                    self->pkt.len = 0;
                    return (core_object_t*)&self->pkt;
                } else {
                    self->errs++;
                }
                return 0;
            }
        }
        n = recvfrom(self->fd, self->recvbuf, sizeof(self->recvbuf), 0, 0, 0);
        if (n > -1) {
            break;
        }
        switch (errno) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
        case EINTR:
            if (self->nonblocking) {
                self->pkt.len = 0;
                return (core_object_t*)&self->pkt;
            }
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

    self->pkts_recv++;
    self->pkt.len = n;
    return (core_object_t*)&self->pkt;
}

static const core_object_t* _produce_tcp(output_dnscli_t* self)
{
    ssize_t n;
    mlassert_self();

    if (self->have_pkt) {
        if (self->recv > self->dnslen + sizeof(self->dnslen)) {
            self->recv -= self->dnslen + sizeof(self->dnslen);
            memmove(self->recvbuf, self->recvbuf + self->dnslen + sizeof(self->dnslen), self->recv);
        } else {
            self->recv = 0;
        }
        self->have_pkt    = 0;
        self->have_dnslen = 0;
    }

    if (!self->have_dnslen && self->recv >= sizeof(self->dnslen)) {
        self->dnslen      = _need16(self->recvbuf);
        self->have_dnslen = 1;
    }
    if (self->have_dnslen && self->recv >= self->dnslen + sizeof(self->dnslen)) {
        self->pkts_recv++;
        self->pkt.len  = self->dnslen + sizeof(self->dnslen);
        self->have_pkt = 1;
        return (core_object_t*)&self->pkt;
    }

    for (;;) {
        if (self->poll_timeout) {
            self->poll.events = POLLIN;
            n                 = poll(&self->poll, 1, self->poll_timeout);
            if (n != 1 || !(self->poll.revents & POLLIN)) {
                if (!n) {
                    self->timeouts++;
                    self->pkt.len = 0;
                    return (core_object_t*)&self->pkt;
                } else {
                    self->errs++;
                }
                return 0;
            }
        }
        n = recvfrom(self->fd, self->recvbuf + self->recv, sizeof(self->recvbuf) - self->recv, 0, 0, 0);
        if (n > 0) {
            self->recv += n;

            if (!self->have_dnslen && self->recv >= sizeof(self->dnslen)) {
                self->dnslen      = _need16(self->recvbuf);
                self->have_dnslen = 1;
            }
            if (self->have_dnslen && self->recv >= self->dnslen + sizeof(self->dnslen)) {
                self->pkts_recv++;
                self->pkt.len  = self->dnslen + sizeof(self->dnslen);
                self->have_pkt = 1;
                return (core_object_t*)&self->pkt;
            }

            if (self->nonblocking) {
                break;
            }
            continue;
        }
        if (!n) {
            break;
        }
        switch (errno) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
        case EINTR:
            if (self->nonblocking) {
                self->pkt.len = 0;
                return (core_object_t*)&self->pkt;
            }
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

    self->pkt.len = 0;
    return (core_object_t*)&self->pkt;
}

static const core_object_t* _produce_tls(output_dnscli_t* self)
{
    ssize_t n;
    mlassert_self();

    if (self->have_pkt) {
        if (self->recv > self->dnslen + sizeof(self->dnslen)) {
            self->recv -= self->dnslen + sizeof(self->dnslen);
            memmove(self->recvbuf, self->recvbuf + self->dnslen + sizeof(self->dnslen), self->recv);
        } else {
            self->recv = 0;
        }
        self->have_pkt    = 0;
        self->have_dnslen = 0;
    }

    if (!self->have_dnslen && self->recv >= sizeof(self->dnslen)) {
        self->dnslen      = _need16(self->recvbuf);
        self->have_dnslen = 1;
    }
    if (self->have_dnslen && self->recv >= self->dnslen + sizeof(self->dnslen)) {
        self->pkts_recv++;
        self->pkt.len  = self->dnslen + sizeof(self->dnslen);
        self->have_pkt = 1;
        return (core_object_t*)&self->pkt;
    }

    for (;;) {
        if (!gnutls_record_check_pending(self->session) && self->poll_timeout) {
            self->poll.events = POLLIN;
            n                 = poll(&self->poll, 1, self->poll_timeout);
            if (n != 1 || !(self->poll.revents & POLLIN)) {
                if (!n) {
                    self->timeouts++;
                    self->pkt.len = 0;
                    return (core_object_t*)&self->pkt;
                } else {
                    self->errs++;
                }
                return 0;
            }
        }
        n = gnutls_record_recv(self->session, self->recvbuf + self->recv, sizeof(self->recvbuf) - self->recv);
        if (n > 0) {
            self->recv += n;

            if (!self->have_dnslen && self->recv >= sizeof(self->dnslen)) {
                self->dnslen      = _need16(self->recvbuf);
                self->have_dnslen = 1;
            }
            if (self->have_dnslen && self->recv >= self->dnslen + sizeof(self->dnslen)) {
                self->pkts_recv++;
                self->pkt.len  = self->dnslen + sizeof(self->dnslen);
                self->have_pkt = 1;
                return (core_object_t*)&self->pkt;
            }

            if (self->nonblocking) {
                break;
            }
            continue;
        }
        if (!n) {
            break;
        }
        switch (n) {
        case GNUTLS_E_AGAIN:
        case GNUTLS_E_TIMEDOUT:
        case GNUTLS_E_INTERRUPTED:
            if (self->nonblocking) {
                self->pkt.len = 0;
                return (core_object_t*)&self->pkt;
            }
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

    self->pkt.len = 0;
    return (core_object_t*)&self->pkt;
}

core_producer_t output_dnscli_producer(output_dnscli_t* self)
{
    mlassert_self();

    if (!self->conn_ok) {
        lfatal("not connected");
    }

    switch (self->mode & OUTPUT_DNSCLI_MODE_MODES) {
    case OUTPUT_DNSCLI_MODE_UDP:
        return (core_producer_t)_produce_udp;
    case OUTPUT_DNSCLI_MODE_TCP:
        return (core_producer_t)_produce_tcp;
    case OUTPUT_DNSCLI_MODE_TLS:
        return (core_producer_t)_produce_tls;
    default:
        break;
    }

    lfatal("internal error");
    return 0;
}

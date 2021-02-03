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

#include "output/tcpcli.h"
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

static core_log_t      _log      = LOG_T_INIT("output.tcpcli");
static output_tcpcli_t _defaults = {
    LOG_T_INIT_OBJ("output.tcpcli"),
    0, 0, -1,
    { 0 }, CORE_OBJECT_PAYLOAD_INIT(0),
    0, 0, 0, 0,
    { 5, 0 }, 1
};

core_log_t* output_tcpcli_log()
{
    return &_log;
}

void output_tcpcli_init(output_tcpcli_t* self)
{
    mlassert_self();

    *self             = _defaults;
    self->pkt.payload = self->recvbuf;
}

void output_tcpcli_destroy(output_tcpcli_t* self)
{
    mlassert_self();

    if (self->fd > -1) {
        shutdown(self->fd, SHUT_RDWR);
        close(self->fd);
    }
}

int output_tcpcli_connect(output_tcpcli_t* self, const char* host, const char* port)
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
    return 0;
}

int output_tcpcli_nonblocking(output_tcpcli_t* self)
{
    int flags;
    mlassert_self();

    if (self->fd < 0) {
        lfatal("not connected");
    }

    flags = fcntl(self->fd, F_GETFL);
    if (flags != -1) {
        flags = flags & O_NONBLOCK ? 1 : 0;
    }

    return flags;
}

int output_tcpcli_set_nonblocking(output_tcpcli_t* self, int nonblocking)
{
    int flags;
    mlassert_self();

    if (self->fd < 0) {
        lfatal("not connected");
    }

    if ((flags = fcntl(self->fd, F_GETFL)) == -1) {
        lcritical("fcntl(FL_GETFL) error %s", core_log_errstr(errno));
        return -1;
    }

    if (nonblocking) {
        flags |= O_NONBLOCK;
        self->blocking = 0;
    } else {
        flags &= ~O_NONBLOCK;
        self->blocking = 1;
    }

    if (fcntl(self->fd, F_SETFL, flags | O_NONBLOCK)) {
        lcritical("fcntl(FL_SETFL, %x) error %s", flags, core_log_errstr(errno));
        return -1;
    }

    return 0;
}

static void _receive(output_tcpcli_t* self, const core_object_t* obj)
{
    const uint8_t* payload;
    size_t         len, sent;
    uint16_t       dnslen;
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
            ssize_t ret = sendto(self->fd, ((uint8_t*)&dnslen) + sent, sizeof(dnslen) - sent, 0, 0, 0);
            if (ret > -1) {
                sent += ret;
                if (sent < sizeof(dnslen))
                    continue;

                sent = 0;
                for (;;) {
                    ssize_t ret = sendto(self->fd, payload + sent, len - sent, 0, 0, 0);
                    if (ret > -1) {
                        sent += ret;
                        if (sent < len)
                            continue;
                        self->pkts++;
                        return;
                    }
                    switch (errno) {
                    case EAGAIN:
#if EAGAIN != EWOULDBLOCK
                    case EWOULDBLOCK:
#endif
                        continue;
                    default:
                        break;
                    }
                    break;
                }
                self->errs++;
                return;
            }
            switch (errno) {
            case EAGAIN:
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
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

core_receiver_t output_tcpcli_receiver(output_tcpcli_t* self)
{
    mlassert_self();

    if (self->fd < 0) {
        lfatal("not connected");
    }

    return (core_receiver_t)_receive;
}

static const core_object_t* _produce(output_tcpcli_t* self)
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
                self->pkt.len     = self->dnslen;
                self->have_dnslen = 0;
                return (core_object_t*)&self->pkt;
            }
        }
    }

    if (self->blocking) {
        p.fd      = self->fd;
        p.events  = POLLIN;
        p.revents = 0;
        to        = (self->timeout.sec * 1e3) + (self->timeout.nsec / 1e6); //NOSONAR
        if (!to) {
            to = 1;
        }
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

            n = recvfrom(self->fd, ((uint8_t*)&dnslen) + recv, sizeof(dnslen) - recv, 0, 0, 0);
            if (n > 0) {
                recv += n;
                if (recv < sizeof(dnslen))
                    continue;
                break;
            }
            if (!n) {
                break;
            }
            switch (errno) {
            case EAGAIN:
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
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
        self->have_dnslen = 1;
        self->recv        = 0;
    }

    for (;;) {
        n = poll(&p, 1, to);
        if (n < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            self->errs++;
            return 0;
        }
        if (!n || !(p.revents & POLLIN)) {
            self->pkt.len = 0;
            return (core_object_t*)&self->pkt;
        }

        n = recvfrom(self->fd, self->recvbuf + self->recv, sizeof(self->recvbuf) - self->recv, 0, 0, 0);
        if (n > 0) {
            self->recv += n;
            if (self->recv < self->dnslen)
                continue;
            break;
        }
        if (!n) {
            break;
        }
        switch (errno) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
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

core_producer_t output_tcpcli_producer(output_tcpcli_t* self)
{
    mlassert_self();

    if (self->fd < 0) {
        lfatal("not connected");
    }

    return (core_producer_t)_produce;
}

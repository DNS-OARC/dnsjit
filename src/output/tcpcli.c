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

#include "output/tcpcli.h"
#include "core/object/dns.h"
#include "core/object/payload.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

static core_log_t      _log      = LOG_T_INIT("output.tcpcli");
static output_tcpcli_t _defaults = {
    LOG_T_INIT_OBJ("output.tcpcli"),
    0, 0, -1,
    { 0 }, CORE_OBJECT_PACKET_INIT(0),
    0, 0, 0
};

core_log_t* output_tcpcli_log()
{
    return &_log;
}

int output_tcpcli_init(output_tcpcli_t* self)
{
    if (!self) {
        return 1;
    }

    *self             = _defaults;
    self->pkt.payload = self->recvbuf;

    ldebug("init");

    return 0;
}

int output_tcpcli_destroy(output_tcpcli_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    if (self->fd > -1) {
        shutdown(self->fd, SHUT_RDWR);
        close(self->fd);
    }

    return 0;
}

int output_tcpcli_connect(output_tcpcli_t* self, const char* host, const char* port)
{
    struct addrinfo* addr;
    int              err;

    if (!self || self->fd > -1 || !host || !port) {
        return 1;
    }

    ldebug("connect %s %s", host, port);

    if ((err = getaddrinfo(host, port, 0, &addr))) {
        lcritical("getaddrinfo() %d", err);
        return 1;
    }
    if (!addr) {
        lcritical("getaddrinfo failed");
        return 1;
    }
    ldebug("getaddrinfo() flags: 0x%x family: 0x%x socktype: 0x%x protocol: 0x%x addrlen: %d",
        addr->ai_flags,
        addr->ai_family,
        addr->ai_socktype,
        addr->ai_protocol,
        addr->ai_addrlen);

    if ((self->fd = socket(addr->ai_addr->sa_family, SOCK_STREAM, 0)) < 0) {
        lcritical("socket failed");
        freeaddrinfo(addr);
        return 1;
    }

    if (connect(self->fd, addr->ai_addr, addr->ai_addrlen)) {
        lcritical("connect failed");
        freeaddrinfo(addr);
        close(self->fd);
        self->fd = -1;
        return 1;
    }

    freeaddrinfo(addr);
    return 0;
}

int output_tcpcli_nonblocking(output_tcpcli_t* self)
{
    int flags;

    if (!self || self->fd < 0) {
        return -1;
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

    if (!self || self->fd < 0) {
        return 1;
    }

    ldebug("set nonblocking %d", nonblocking);

    if ((flags = fcntl(self->fd, F_GETFL)) == -1) {
        lcritical("fcntl(FL_GETFL) failed");
        return 1;
    }

    if (nonblocking) {
        if (fcntl(self->fd, F_SETFL, flags | O_NONBLOCK)) {
            lcritical("fcntl(FL_SETFL) failed");
            return 1;
        }
    } else {
        if (fcntl(self->fd, F_SETFL, flags & ~O_NONBLOCK)) {
            lcritical("fcntl(FL_SETFL) failed");
            return 1;
        }
    }

    return 0;
}

static int _receive(void* ctx, const core_object_t* obj)
{
    output_tcpcli_t* self = (output_tcpcli_t*)ctx;
    const uint8_t*   payload;
    size_t           len, sent;
    uint16_t         dnslen;

    if (!self) {
        return 1;
    }

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
            return 1;
        }

        if (len < 3 || payload[2] & 0x80) {
            return 0;
        }

        sent = 0;
        self->pkts++;

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
                        return 0;
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
        break;
    }

    return 1;
}

core_receiver_t output_tcpcli_receiver()
{
    return _receive;
}

static const core_object_t* _produce(void* ctx)
{
    output_tcpcli_t* self = (output_tcpcli_t*)ctx;
    ssize_t          n, recv;
    uint16_t         dnslen;

    if (!self || self->fd < 0) {
        return 0;
    }

    if (!self->have_dnslen) {
        recv = 0;
        for (;;) {
            n = recvfrom(self->fd, ((uint8_t*)&dnslen) + recv, sizeof(dnslen) - recv, 0, 0, 0);
            if (n > -1) {
                recv += n;
                if (recv < sizeof(dnslen))
                    continue;
                break;
            }
            switch (errno) {
            case EAGAIN:
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
                n = 0;
                break;
            default:
                break;
            }
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
        n = recvfrom(self->fd, self->recvbuf, sizeof(self->recvbuf), 0, 0, 0);
        if (n > -1) {
            self->recv += n;
            if (self->recv < self->dnslen)
                continue;
            break;
        }
        switch (errno) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
            n = 0;
            break;
        default:
            break;
        }
        break;
    }

    if (n < 1) {
        return 0;
    }

    // TODO: recv more then dnslen

    self->pkt.len     = self->dnslen;
    self->have_dnslen = 0;
    return (core_object_t*)&self->pkt;
}

core_producer_t output_tcpcli_producer()
{
    return _produce;
}

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

#include "output/udpcli.h"
#include "core/object/dns.h"
#include "core/object/payload.h"

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

static core_log_t      _log      = LOG_T_INIT("output.udpcli");
static output_udpcli_t _defaults = {
    LOG_T_INIT_OBJ("output.udpcli"),
    0, 0, -1,
    { 0 }, 0,
    { 0 }, CORE_OBJECT_PACKET_INIT(0)
};

core_log_t* output_udpcli_log()
{
    return &_log;
}

int output_udpcli_init(output_udpcli_t* self)
{
    if (!self) {
        return 1;
    }

    *self             = _defaults;
    self->pkt.payload = self->recvbuf;

    ldebug("init");

    return 0;
}

int output_udpcli_destroy(output_udpcli_t* self)
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

int output_udpcli_connect(output_udpcli_t* self, const char* host, const char* port)
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

    memcpy(&self->addr, addr->ai_addr, addr->ai_addrlen);
    self->addr_len = addr->ai_addrlen;
    freeaddrinfo(addr);

    if ((self->fd = socket(((struct sockaddr*)&self->addr)->sa_family, SOCK_DGRAM, 0)) < 0) {
        lcritical("socket failed");
        return 1;
    }

    return 0;
}

int output_udpcli_nonblocking(output_udpcli_t* self)
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

int output_udpcli_set_nonblocking(output_udpcli_t* self, int nonblocking)
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
    output_udpcli_t* self = (output_udpcli_t*)ctx;
    const uint8_t*   payload;
    size_t           len, sent;

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
        for (;;) {
            ssize_t ret = sendto(self->fd, payload + sent, len - sent, 0, (struct sockaddr*)&self->addr, self->addr_len);
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

    return 1;
}

core_receiver_t output_udpcli_receiver()
{
    return _receive;
}

static const core_object_t* _produce(void* ctx)
{
    output_udpcli_t* self = (output_udpcli_t*)ctx;
    ssize_t          n;

    if (!self || self->fd < 0) {
        return 0;
    }

    for (;;) {
        n = recvfrom(self->fd, self->recvbuf, sizeof(self->recvbuf), 0, 0, 0);
        if (n > -1) {
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

    self->pkt.len = n;
    return (core_object_t*)&self->pkt;
}

core_producer_t output_udpcli_producer()
{
    return _produce;
}

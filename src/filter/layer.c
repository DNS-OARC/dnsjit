/*
 * Copyright (c) 2018-2020, OARC, Inc.
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

#include "filter/layer.h"
#include "core/assert.h"

#include <string.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_NET_ETHERTYPES_H
#include <net/ethertypes.h>
#endif
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

#define N_IEEE802 3

static core_log_t     _log      = LOG_T_INIT("filter.layer");
static filter_layer_t _defaults = {
    LOG_T_INIT_OBJ("filter.layer"),
    0, 0,
    0, 0,
    0,
    CORE_OBJECT_NULL_INIT(0),
    CORE_OBJECT_ETHER_INIT(0),
    CORE_OBJECT_LOOP_INIT(0),
    CORE_OBJECT_LINUXSLL_INIT(0),
    0, { CORE_OBJECT_IEEE802_INIT(0), CORE_OBJECT_IEEE802_INIT(0), CORE_OBJECT_IEEE802_INIT(0) },
    CORE_OBJECT_IP_INIT(0),
    CORE_OBJECT_IP6_INIT(0),
    CORE_OBJECT_GRE_INIT(0),
    CORE_OBJECT_ICMP_INIT(0),
    CORE_OBJECT_ICMP6_INIT(0),
    CORE_OBJECT_UDP_INIT(0),
    CORE_OBJECT_TCP_INIT(0),
    CORE_OBJECT_PAYLOAD_INIT(0)
};

core_log_t* filter_layer_log()
{
    return &_log;
}

void filter_layer_init(filter_layer_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void filter_layer_destroy(filter_layer_t* self)
{
    mlassert_self();
}

#define need4x2(v1, v2, p, l) \
    if (l < 1) {              \
        break;                \
    }                         \
    v1 = (*p) >> 4;           \
    v2 = (*p) & 0xf;          \
    p += 1;                   \
    l -= 1

#define need8(v, p, l) \
    if (l < 1) {       \
        break;         \
    }                  \
    v = *p;            \
    p += 1;            \
    l -= 1

static inline uint16_t _need16(const void* ptr)
{
    uint16_t v;
    memcpy(&v, ptr, sizeof(v));
    return be16toh(v);
}

#define need16(v, p, l) \
    if (l < 2) {        \
        break;          \
    }                   \
    v = _need16(p);     \
    p += 2;             \
    l -= 2

#define needr16(v, p, l)      \
    if (l < 2) {              \
        break;                \
    }                         \
    v = bswap_16(_need16(p)); \
    p += 2;                   \
    l -= 2

static inline uint32_t _need32(const void* ptr)
{
    uint32_t v;
    memcpy(&v, ptr, sizeof(v));
    return be32toh(v);
}

#define need32(v, p, l) \
    if (l < 4) {        \
        break;          \
    }                   \
    v = _need32(p);     \
    p += 4;             \
    l -= 4

#define needr32(v, p, l)      \
    if (l < 4) {              \
        break;                \
    }                         \
    v = bswap_32(_need32(p)); \
    p += 4;                   \
    l -= 4

#define needxb(b, x, p, l) \
    if (l < x) {           \
        break;             \
    }                      \
    memcpy(b, p, x);       \
    p += x;                \
    l -= x

#define advancexb(x, p, l) \
    if (l < x) {           \
        break;             \
    }                      \
    p += x;                \
    l -= x

//static int _ip(filter_layer_t* self, const core_object_t* obj, const unsigned char* pkt, size_t len);

static inline int _proto(filter_layer_t* self, uint8_t proto, const core_object_t* obj, const unsigned char* pkt, size_t len)
{
    switch (proto) {
    case IPPROTO_GRE: {
        core_object_gre_t* gre = &self->gre;
        gre->obj_prev          = obj;

        need16(gre->gre_flags, pkt, len);
        need16(gre->ether_type, pkt, len);

        /* TODO: Incomplete, check RFC 1701 */

        self->produced = (core_object_t*)gre;

        // if (gre.gre_flags & 0x1) {
        //     need16(gre.checksum, pkt, len);
        // }
        // if (gre.gre_flags & 0x4) {
        //     need16(gre.key, pkt, len);
        // }
        // if (gre.gre_flags & 0x8) {
        //     need16(gre.sequence, pkt, len);
        // }
        //
        // switch (gre.ether_type) {
        // case ETHERTYPE_IP:
        // case ETHERTYPE_IPV6:
        //     return _ip(self, (core_object_t*)gre, pkt, len);
        //
        // default:
        //     break;
        // }
        break;
    }
    case IPPROTO_ICMP: {
        core_object_icmp_t* icmp = &self->icmp;
        icmp->obj_prev           = obj;

        need8(icmp->type, pkt, len);
        need8(icmp->code, pkt, len);
        need16(icmp->cksum, pkt, len);

        self->produced = (core_object_t*)icmp;
        break;
    }
    case IPPROTO_ICMPV6: {
        core_object_icmp6_t* icmp6 = &self->icmp6;
        icmp6->obj_prev            = obj;

        need8(icmp6->type, pkt, len);
        need8(icmp6->code, pkt, len);
        need16(icmp6->cksum, pkt, len);

        self->produced = (core_object_t*)icmp6;
        break;
    }
    case IPPROTO_UDP: {
        core_object_udp_t*     udp     = &self->udp;
        core_object_payload_t* payload = &self->payload;
        udp->obj_prev                  = obj;

        need16(udp->sport, pkt, len);
        need16(udp->dport, pkt, len);
        need16(udp->ulen, pkt, len);
        need16(udp->sum, pkt, len);

        payload->obj_prev = (core_object_t*)udp;

        /* Check for padding */
        if (len > udp->ulen) {
            payload->padding = len - udp->ulen;
            payload->len     = len - payload->padding;
        } else {
            payload->padding = 0;
            payload->len     = len;
        }
        payload->payload = (uint8_t*)pkt;

        self->produced = (core_object_t*)payload;
        break;
    }
    case IPPROTO_TCP: {
        core_object_tcp_t*     tcp     = &self->tcp;
        core_object_payload_t* payload = &self->payload;
        tcp->obj_prev                  = obj;

        need16(tcp->sport, pkt, len);
        need16(tcp->dport, pkt, len);
        need32(tcp->seq, pkt, len);
        need32(tcp->ack, pkt, len);
        need4x2(tcp->off, tcp->x2, pkt, len);
        need8(tcp->flags, pkt, len);
        need16(tcp->win, pkt, len);
        need16(tcp->sum, pkt, len);
        need16(tcp->urp, pkt, len);
        if (tcp->off > 5) {
            tcp->opts_len = (tcp->off - 5) * 4;
            needxb(tcp->opts, tcp->opts_len, pkt, len);
        } else {
            tcp->opts_len = 0;
        }

        payload->obj_prev = (core_object_t*)tcp;

        /* Check for padding */
        if (obj->obj_type == CORE_OBJECT_IP && len > (((const core_object_ip_t*)obj)->len - (((const core_object_ip_t*)obj)->hl * 4))) {
            payload->padding = len - (((const core_object_ip_t*)obj)->len - (((const core_object_ip_t*)obj)->hl * 4));
            payload->len     = len - payload->padding;
        } else if (obj->obj_type == CORE_OBJECT_IP6 && len > ((const core_object_ip6_t*)obj)->plen) {
            payload->padding = len - ((const core_object_ip6_t*)obj)->plen;
            payload->len     = len - payload->padding;
        } else {
            payload->padding = 0;
            payload->len     = len;
        }

        payload->payload = (uint8_t*)pkt;

        self->produced = (core_object_t*)payload;
        break;
    }
    default:
        self->produced = obj;
        break;
    }

    return 0;
}

static inline int _ip(filter_layer_t* self, const core_object_t* obj, const unsigned char* pkt, size_t len)
{
    if (len) {
        switch ((*pkt >> 4)) {
        case 4: {
            core_object_ip_t* ip = &self->ip;

            ip->obj_prev = obj;

            need4x2(ip->v, ip->hl, pkt, len);
            need8(ip->tos, pkt, len);
            need16(ip->len, pkt, len);
            need16(ip->id, pkt, len);
            need16(ip->off, pkt, len);
            need8(ip->ttl, pkt, len);
            need8(ip->p, pkt, len);
            need16(ip->sum, pkt, len);
            needxb(&ip->src, 4, pkt, len);
            needxb(&ip->dst, 4, pkt, len);

            /* TODO: IPv4 options */

            if (ip->hl < 5)
                break;
            if (ip->hl > 5) {
                advancexb((ip->hl - 5) * 4, pkt, len);
            }

            /* Check reported length for missing payload */
            if (ip->len < (ip->hl * 4)) {
                break;
            }
            if (len < (ip->len - (ip->hl * 4))) {
                break;
            }

            if (ip->off & 0x2000 || ip->off & 0x1fff) {
                core_object_payload_t* payload = &self->payload;

                payload->obj_prev = (core_object_t*)ip;

                /* Check for padding */
                if (len > (ip->len - (ip->hl * 4))) {
                    payload->padding = len - (ip->len - (ip->hl * 4));
                    payload->len     = len - payload->padding;
                } else {
                    payload->padding = 0;
                    payload->len     = len;
                }
                payload->payload = (uint8_t*)pkt;

                self->produced = (core_object_t*)payload;
                return 0;
            }

            return _proto(self, ip->p, (core_object_t*)ip, pkt, len);
        }
        case 6: {
            core_object_ip6_t* ip6 = &self->ip6;
            struct ip6_ext     ext;

            ip6->obj_prev = obj;
            ip6->is_frag = ip6->have_rtdst = 0;

            need32(ip6->flow, pkt, len);
            need16(ip6->plen, pkt, len);
            need8(ip6->nxt, pkt, len);
            need8(ip6->hlim, pkt, len);
            needxb(&ip6->src, 16, pkt, len);
            needxb(&ip6->dst, 16, pkt, len);

            /* Check reported length for missing payload */
            if (len < ip6->plen) {
                break;
            }

            ext.ip6e_nxt = ip6->nxt;
            ext.ip6e_len = 0;
            while (ext.ip6e_nxt != IPPROTO_NONE
                   && ext.ip6e_nxt != IPPROTO_GRE
                   && ext.ip6e_nxt != IPPROTO_ICMPV6
                   && ext.ip6e_nxt != IPPROTO_UDP
                   && ext.ip6e_nxt != IPPROTO_TCP) {

                /*
                 * Advance to the start of next header, this may not be needed
                 * if it's the first header or if the header is supported.
                 */
                if (ext.ip6e_len) {
                    advancexb(ext.ip6e_len * 8, pkt, len);
                }

                /* TODO: Store IPv6 headers? */

                /* Handle supported headers */
                if (ext.ip6e_nxt == IPPROTO_FRAGMENT) {
                    if (ip6->is_frag) {
                        return 1;
                    }
                    need8(ext.ip6e_nxt, pkt, len);
                    need8(ext.ip6e_len, pkt, len);
                    if (ext.ip6e_len) {
                        return 1;
                    }
                    need16(ip6->frag_offlg, pkt, len);
                    need32(ip6->frag_ident, pkt, len);
                    ip6->is_frag = 1;
                } else if (ext.ip6e_nxt == IPPROTO_ROUTING) {
                    struct ip6_rthdr rthdr;

                    if (ip6->have_rtdst) {
                        return 1;
                    }

                    need8(ext.ip6e_nxt, pkt, len);
                    need8(ext.ip6e_len, pkt, len);
                    need8(rthdr.ip6r_type, pkt, len);
                    need8(rthdr.ip6r_segleft, pkt, len);
                    advancexb(4, pkt, len);

                    if (!rthdr.ip6r_type && rthdr.ip6r_segleft) {
                        if (ext.ip6e_len & 1) {
                            return 1;
                        }
                        if (ext.ip6e_len > 2) {
                            advancexb(ext.ip6e_len - 2, pkt, len);
                        }
                        needxb(ip6->rtdst, 16, pkt, len);
                        ip6->have_rtdst = 1;
                    }
                } else {
                    need8(ext.ip6e_nxt, pkt, len);
                    need8(ext.ip6e_len, pkt, len);
                    advancexb(6, pkt, len);
                }
            }

            if (ext.ip6e_nxt == IPPROTO_NONE || ip6->is_frag) {
                core_object_payload_t* payload = &self->payload;

                payload->obj_prev = (core_object_t*)ip6;

                /* Check for padding */
                if (len > ip6->plen) {
                    payload->padding = len - ip6->plen;
                    payload->len     = len - payload->padding;
                } else {
                    payload->padding = 0;
                    payload->len     = len;
                }
                payload->payload = (uint8_t*)pkt;

                self->produced = (core_object_t*)payload;
                return 0;
            }

            return _proto(self, ext.ip6e_nxt, (core_object_t*)ip6, pkt, len);
        }
        default:
            break;
        }
    }

    self->produced = obj;

    return 0;
}

static inline int _ieee802(filter_layer_t* self, uint16_t tpid, const core_object_t* obj, const unsigned char* pkt, size_t len)
{
    core_object_ieee802_t* ieee802 = &self->ieee802[self->n_ieee802];
    uint16_t               tci;

    ieee802->obj_prev = obj;

    for (;;) {
        ieee802->tpid = tpid;
        need16(tci, pkt, len);
        ieee802->pcp = (tci & 0xe000) >> 13;
        ieee802->dei = (tci & 0x1000) >> 12;
        ieee802->vid = tci & 0x0fff;
        need16(ieee802->ether_type, pkt, len);

        switch (ieee802->ether_type) {
        case 0x88a8: /* 802.1ad */
        case 0x9100: /* 802.1 QinQ non-standard */
            self->n_ieee802++;
            if (self->n_ieee802 < N_IEEE802) {
                obj               = (const core_object_t*)ieee802;
                ieee802           = &self->ieee802[self->n_ieee802];
                ieee802->obj_prev = obj;
                tpid              = ieee802->ether_type;
                continue;
            }
            return 1;

        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            return _ip(self, (core_object_t*)ieee802, pkt, len);

        default:
            break;
        }
        break;
    }

    self->produced = obj;

    return 0;
}

static inline int _link(filter_layer_t* self, const core_object_pcap_t* pcap)
{
    const unsigned char* pkt;
    size_t               len;

    self->n_ieee802 = 0;

    pkt = pcap->bytes;
    len = pcap->caplen;

    switch (pcap->linktype) {
    case DLT_NULL: {
        core_object_null_t* null = &self->null;
        null->obj_prev           = (core_object_t*)pcap;

        if (pcap->is_swapped) {
            needr32(null->family, pkt, len);
        } else {
            need32(null->family, pkt, len);
        }

        switch (null->family) {
        case 2:
        case 24:
        case 28:
        case 30:
            return _ip(self, (core_object_t*)null, pkt, len);

        default:
            break;
        }
        break;
    }
    case DLT_EN10MB: {
        core_object_ether_t* ether = &self->ether;
        ether->obj_prev            = (core_object_t*)pcap;

        needxb(ether->dhost, 6, pkt, len);
        needxb(ether->shost, 6, pkt, len);
        need16(ether->type, pkt, len);

        switch (ether->type) {
        case 0x8100: /* 802.1q */
        case 0x88a8: /* 802.1ad */
        case 0x9100: /* 802.1 QinQ non-standard */
            return _ieee802(self, ether->type, (core_object_t*)ether, pkt, len);

        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            return _ip(self, (core_object_t*)ether, pkt, len);

        default:
            break;
        }
        break;
    }
    case DLT_LOOP: {
        core_object_loop_t* loop = &self->loop;
        loop->obj_prev           = (core_object_t*)pcap;

        need32(loop->family, pkt, len);

        switch (loop->family) {
        case 2:
        case 24:
        case 28:
        case 30:
            return _ip(self, (core_object_t*)loop, pkt, len);

        default:
            break;
        }
        break;
    }
    case DLT_RAW:
#ifdef DLT_IPV4
    case DLT_IPV4:
#endif
#ifdef DLT_IPV6
    case DLT_IPV6:
#endif
        return _ip(self, (core_object_t*)pcap, pkt, len);
    case DLT_LINUX_SLL: {
        core_object_linuxsll_t* linuxsll = &self->linuxsll;
        linuxsll->obj_prev               = (core_object_t*)pcap;

        need16(linuxsll->packet_type, pkt, len);
        need16(linuxsll->arp_hardware, pkt, len);
        need16(linuxsll->link_layer_address_length, pkt, len);
        needxb(linuxsll->link_layer_address, 8, pkt, len);
        need16(linuxsll->ether_type, pkt, len);

        switch (linuxsll->ether_type) {
        case 0x8100: /* 802.1q */
        case 0x88a8: /* 802.1ad */
        case 0x9100: /* 802.1 QinQ non-standard */
            return _ieee802(self, linuxsll->ether_type, (core_object_t*)linuxsll, pkt, len);

        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            return _ip(self, (core_object_t*)linuxsll, pkt, len);

        default:
            break;
        }
        break;
    }
    /* TODO: These might be interesting to implement
        case DLT_IPNET:
        case DLT_PKTAP:
        */
    default:
        break;
    }

    self->produced = (core_object_t*)pcap;

    return 0;
}

static void _receive(filter_layer_t* self, const core_object_t* obj)
{
    mlassert_self();
    lassert(obj, "obj is nil");

    if (!self->recv) {
        lfatal("no receiver set");
    }
    if (obj->obj_type != CORE_OBJECT_PCAP) {
        lfatal("obj is not CORE_OBJECT_PCAP");
    }

    if (!_link(self, (core_object_pcap_t*)obj)) {
        self->recv(self->ctx, self->produced);
    }
}

core_receiver_t filter_layer_receiver()
{
    return (core_receiver_t)_receive;
}

static const core_object_t* _produce(filter_layer_t* self)
{
    const core_object_t* obj;
    mlassert_self();

    obj = self->prod(self->prod_ctx);
    if (!obj || obj->obj_type != CORE_OBJECT_PCAP || _link(self, (core_object_pcap_t*)obj)) {
        return 0;
    }

    return self->produced;
}

core_producer_t filter_layer_producer(filter_layer_t* self)
{
    mlassert_self();

    if (!self->prod) {
        lfatal("no producer set");
    }

    return (core_producer_t)_produce;
}

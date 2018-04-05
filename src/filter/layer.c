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

#include "filter/layer.h"
#include "core/object/pcap.h"
#include "core/object/null.h"
#include "core/object/ether.h"
#include "core/object/loop.h"
#include "core/object/linuxsll.h"
#include "core/object/ieee802.h"
#include "core/object/ip.h"
#include "core/object/ip6.h"
#include "core/object/gre.h"
#include "core/object/icmp.h"
#include "core/object/icmp6.h"
#include "core/object/udp.h"
#include "core/object/tcp.h"

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

static core_log_t     _log      = LOG_T_INIT("filter.layer");
static filter_layer_t _defaults = {
    LOG_T_INIT_OBJ("filter.layer"),
    0, 0
};

core_log_t* filter_layer_log()
{
    return &_log;
}

int filter_layer_init(filter_layer_t* self)
{
    if (!self) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    return 0;
}

int filter_layer_destroy(filter_layer_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

    return 0;
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

#define need16(v, p, l)       \
    if (l < 2) {              \
        break;                \
    }                         \
    v = (*p << 8) | *(p + 1); \
    p += 2;                   \
    l -= 2

#define needr16(v, p, l)      \
    if (l < 2) {              \
        break;                \
    }                         \
    v = *p | (*(p + 1) << 8); \
    p += 2;                   \
    l -= 2

#define need32(v, p, l)                                             \
    if (l < 4) {                                                    \
        break;                                                      \
    }                                                               \
    v = (*p << 24) | (*(p + 1) << 16) | (*(p + 2) << 8) | *(p + 3); \
    p += 4;                                                         \
    l -= 4

#define needr32(v, p, l)                                            \
    if (l < 4) {                                                    \
        break;                                                      \
    }                                                               \
    v = *p | (*(p + 1) << 8) | (*(p + 2) << 16) | (*(p + 3) << 24); \
    p += 4;                                                         \
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

static int _ip(filter_layer_t* self, const core_object_t* obj, const unsigned char* pkt, size_t len);

static int _proto(filter_layer_t* self, uint8_t proto, const core_object_t* obj, const unsigned char* pkt, size_t len)
{
    switch (proto) {
    case IPPROTO_GRE: {
        core_object_gre_t gre = CORE_OBJECT_GRE_INIT(obj);

        need16(gre.gre_flags, pkt, len);
        need16(gre.ether_type, pkt, len);

        /* TODO: Incomplete, check RFC 1701 */

        self->recv(self->ctx, (core_object_t*)&gre);

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
        //     return _ip(self, (core_object_t*)&gre, pkt, len);
        //
        // default:
        //     break;
        // }
        break;
    }
    case IPPROTO_ICMP: {
        core_object_icmp_t icmp = CORE_OBJECT_ICMP_INIT(obj);

        need8(icmp.type, pkt, len);
        need8(icmp.code, pkt, len);
        need16(icmp.cksum, pkt, len);

        self->recv(self->ctx, (core_object_t*)&icmp);
        break;
    }
    case IPPROTO_ICMPV6: {
        core_object_icmp6_t icmp6 = CORE_OBJECT_ICMP_INIT(obj);

        need8(icmp6.type, pkt, len);
        need8(icmp6.code, pkt, len);
        need16(icmp6.cksum, pkt, len);

        self->recv(self->ctx, (core_object_t*)&icmp6);
        break;
    }
    case IPPROTO_UDP: {
        core_object_udp_t udp = CORE_OBJECT_UDP_INIT(obj);

        need16(udp.sport, pkt, len);
        need16(udp.dport, pkt, len);
        need16(udp.ulen, pkt, len);
        need16(udp.sum, pkt, len);

        udp.payload = (uint8_t*)pkt;
        udp.len     = len;

        self->recv(self->ctx, (core_object_t*)&udp);
        break;
    }
    case IPPROTO_TCP: {
        core_object_tcp_t tcp = CORE_OBJECT_TCP_INIT(obj);

        need16(tcp.sport, pkt, len);
        need16(tcp.dport, pkt, len);
        need32(tcp.seq, pkt, len);
        need32(tcp.ack, pkt, len);
        need4x2(tcp.off, tcp.x2, pkt, len);
        need8(tcp.flags, pkt, len);
        need16(tcp.win, pkt, len);
        need16(tcp.sum, pkt, len);
        need16(tcp.urp, pkt, len);
        if (tcp.off > 5) {
            tcp.opts_len = (tcp.off - 5) * 4;
            needxb(tcp.opts, tcp.opts_len, pkt, len);
        }

        tcp.payload = (uint8_t*)pkt;
        tcp.len     = len;

        self->recv(self->ctx, (core_object_t*)&tcp);
        break;
    }
    default:
        self->recv(self->ctx, obj);
        break;
    }

    return 0;
}

static int _ip(filter_layer_t* self, const core_object_t* obj, const unsigned char* pkt, size_t len)
{
    if (len) {
        switch ((*pkt >> 4)) {
        case 4: {
            core_object_ip_t ip = CORE_OBJECT_IP_INIT(obj);

            need4x2(ip.v, ip.hl, pkt, len);
            need8(ip.tos, pkt, len);
            need16(ip.len, pkt, len);
            need16(ip.id, pkt, len);
            need16(ip.off, pkt, len);
            need8(ip.ttl, pkt, len);
            need8(ip.p, pkt, len);
            need16(ip.sum, pkt, len);
            needxb(&ip.src, 4, pkt, len);
            needxb(&ip.dst, 4, pkt, len);

            /* TODO: IPv4 options */

            if (ip.hl < 5)
                break;
            if (ip.hl > 5) {
                advancexb((ip.hl - 5) * 4, pkt, len);
            }

            /* Check reported length for missing payload or padding */
            if (ip.len < (ip.hl * 4)) {
                break;
            }
            if (len < (ip.len - (ip.hl * 4))) {
                break;
            }
            if (len > (ip.len - (ip.hl * 4))) {
                // TODO: Padding
                // layer_trace("have_ippadding");
                // packet->ippadding      = len - (ip.len - (ip.hl * 4));
                // packet->have_ippadding = 1;
                // len -= packet->ippadding;
            }

            if (ip.off & 0x2000 || ip.off & 0x1fff) {
                ip.payload = (uint8_t*)pkt;
                ip.plen    = len;
                self->recv(self->ctx, (core_object_t*)&ip);
                return 0;
            }

            return _proto(self, ip.p, (core_object_t*)&ip, pkt, len);
        }
        case 6: {
            core_object_ip6_t ip6 = CORE_OBJECT_IP6_INIT(obj);
            struct ip6_ext    ext;
            size_t            already_advanced = 0;

            need32(ip6.flow, pkt, len);
            need16(ip6.plen, pkt, len);
            need8(ip6.nxt, pkt, len);
            need8(ip6.hlim, pkt, len);
            needxb(&ip6.src, 16, pkt, len);
            needxb(&ip6.dst, 16, pkt, len);

            /* Check reported length for missing payload or padding */
            if (len < ip6.plen) {
                break;
            }
            if (len > ip6.plen) {
                // TODO: Padding
                // layer_trace("have_ip6padding");
                // packet->ip6padding      = len - ip6.ip6_plen;
                // packet->have_ip6padding = 1;
                // len -= packet->ip6padding;
            }

            ext.ip6e_nxt = ip6.nxt;
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
                    if (ext.ip6e_len < already_advanced) {
                        ext.ip6e_nxt = IPPROTO_NONE;
                        break;
                    }
                    /* Advance if not already there */
                    else if (ext.ip6e_len > already_advanced) {
                        advancexb((ext.ip6e_len - already_advanced) * 8, pkt, len);
                    }
                    already_advanced = 0;
                } else if (already_advanced) {
                    ext.ip6e_nxt = IPPROTO_NONE;
                    break;
                }

                /* TODO: Store IPv6 headers? */

                /* Handle supported headers */
                if (ext.ip6e_nxt == IPPROTO_FRAGMENT) {
                    break;
                    // if (packet->have_ip6frag) {
                    //     layer_trace("dup ip6frag");
                    //     break;
                    // }
                    // layer_trace("ip6frag");
                    // need8(ext.ip6e_nxt, pkt, len);
                    // need8(packet->ip6frag.ip6f_reserved, pkt, len);
                    // need16(packet->ip6frag.ip6f_offlg, pkt, len);
                    // need32(packet->ip6frag.ip6f_ident, pkt, len);
                    // packet->have_ip6frag = 1;
                    // ext.ip6e_len         = 1;
                    // already_advanced     = 1;
                    // } else if (ext.ip6e_nxt == IPPROTO_ROUTING) {
                    //     struct ip6_rthdr rthdr;
                    //     struct in6_addr  rt[255];
                    //
                    //     if (packet->have_ip6rtdst) {
                    //         layer_trace("dup ip6rtdst");
                    //         break;
                    //     }
                    //     need8(ext.ip6e_nxt, pkt, len);
                    //     need8(ext.ip6e_len, pkt, len);
                    //     need8(rthdr.ip6r_type, pkt, len);
                    //     need8(rthdr.ip6r_segleft, pkt, len);
                    //     if (!rthdr.ip6r_type) {
                    //         if (rthdr.ip6r_segleft > ext.ip6e_len)
                    //             break;
                    //         for (rthdr.ip6r_len = 0; rthdr.ip6r_len < ext.ip6e_len; rthdr.ip6r_len++, already_advanced += 2) {
                    //             needxb(&rt[rthdr.ip6r_len], 16, pkt, len);
                    //         }
                    //         if (!rthdr.ip6r_len || rthdr.ip6r_len != ext.ip6e_len) {
                    //             break;
                    //         }
                    //         if (rthdr.ip6r_segleft) {
                    //             packet->ip6rtdst      = rt[rthdr.ip6r_segleft];
                    //             packet->have_ip6rtdst = 1;
                    //         }
                    //     }
                } else {
                    need8(ext.ip6e_nxt, pkt, len);
                    need8(ext.ip6e_len, pkt, len);
                }

                if (!ext.ip6e_len)
                    break;
            }

            if (ext.ip6e_nxt == IPPROTO_NONE || ext.ip6e_nxt == IPPROTO_FRAGMENT) {
                ip6.payload = (uint8_t*)pkt;
                ip6.len     = len;
                self->recv(self->ctx, (core_object_t*)&ip6);
                return 0;
            }

            return _proto(self, ext.ip6e_nxt, (core_object_t*)&ip6, pkt, len);
        }
        default:
            break;
        }
    }

    self->recv(self->ctx, obj);

    return 0;
}

static int _ieee802(filter_layer_t* self, uint16_t tpid, const core_object_t* obj, const unsigned char* pkt, size_t len)
{
    core_object_ieee802_t ieee802 = CORE_OBJECT_IEEE802_INIT(obj);
    uint16_t              tci;

    for (;;) {
        ieee802.tpid = tpid;
        need16(tci, pkt, len);
        ieee802.pcp = (tci & 0xe000) >> 13;
        ieee802.dei = (tci & 0x1000) >> 12;
        ieee802.vid = tci & 0x0fff;
        need16(ieee802.ether_type, pkt, len);

        switch (ieee802.ether_type) {
        case 0x88a8: /* 802.1ad */
        case 0x9100: /* 802.1 QinQ non-standard */
            return _ieee802(self, ieee802.ether_type, (core_object_t*)&ieee802, pkt, len);

        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            return _ip(self, (core_object_t*)&ieee802, pkt, len);

        default:
            break;
        }
        break;
    }

    self->recv(self->ctx, obj);

    return 0;
}

static int _receive(void* ctx, const core_object_t* obj)
{
    filter_layer_t*      self = (filter_layer_t*)ctx;
    core_object_pcap_t*  pcap = (core_object_pcap_t*)obj;
    const unsigned char* pkt;
    size_t               len;

    if (!self || !obj || obj->obj_type != CORE_OBJECT_PCAP || !self->recv) {
        return 1;
    }

    pkt = pcap->bytes;
    len = pcap->caplen;

    switch (pcap->linktype) {
    case DLT_NULL: {
        core_object_null_t null = CORE_OBJECT_NULL_INIT(pcap);

        if (pcap->is_swapped) {
            needr32(null.family, pkt, len);
        } else {
            need32(null.family, pkt, len);
        }

        switch (null.family) {
        case 2:
        case 24:
        case 28:
        case 30:
            return _ip(self, (core_object_t*)&null, pkt, len);

        default:
            break;
        }
        break;
    }
    case DLT_EN10MB: {
        core_object_ether_t ether = CORE_OBJECT_ETHER_INIT(pcap);

        needxb(ether.dhost, 6, pkt, len);
        needxb(ether.shost, 6, pkt, len);
        need16(ether.type, pkt, len);

        switch (ether.type) {
        case 0x8100: /* 802.1q */
        case 0x88a8: /* 802.1ad */
        case 0x9100: /* 802.1 QinQ non-standard */
            return _ieee802(self, ether.type, (core_object_t*)&ether, pkt, len);

        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            return _ip(self, (core_object_t*)&ether, pkt, len);

        default:
            break;
        }
        break;
    }
    case DLT_LOOP: {
        core_object_loop_t loop = CORE_OBJECT_LOOP_INIT(pcap);

        need32(loop.family, pkt, len);

        switch (loop.family) {
        case 2:
        case 24:
        case 28:
        case 30:
            return _ip(self, (core_object_t*)&loop, pkt, len);

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
        return _ip(self, (core_object_t*)&pcap, pkt, len);
    case DLT_LINUX_SLL: {
        core_object_linuxsll_t linuxsll = CORE_OBJECT_LINUXSLL_INIT(pcap);

        need16(linuxsll.packet_type, pkt, len);
        need16(linuxsll.arp_hardware, pkt, len);
        need16(linuxsll.link_layer_address_length, pkt, len);
        needxb(linuxsll.link_layer_address, 8, pkt, len);
        need16(linuxsll.ether_type, pkt, len);

        switch (linuxsll.ether_type) {
        case 0x8100: /* 802.1q */
        case 0x88a8: /* 802.1ad */
        case 0x9100: /* 802.1 QinQ non-standard */
            return _ieee802(self, linuxsll.ether_type, (core_object_t*)&linuxsll, pkt, len);

        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            return _ip(self, (core_object_t*)&linuxsll, pkt, len);

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

    self->recv(self->ctx, (core_object_t*)pcap);

    return 0;
}

core_receiver_t filter_layer_receiver()
{
    return _receive;
}

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

#include "core/object.h"
#include "core/assert.h"
#include "core/object/pcap.h"
#include "core/object/ether.h"
#include "core/object/null.h"
#include "core/object/loop.h"
#include "core/object/linuxsll.h"
#include "core/object/ieee802.h"
#include "core/object/gre.h"
#include "core/object/ip.h"
#include "core/object/ip6.h"
#include "core/object/icmp.h"
#include "core/object/icmp6.h"
#include "core/object/udp.h"
#include "core/object/tcp.h"
#include "core/object/payload.h"
#include "core/object/dns.h"

core_object_t* core_object_copy(const core_object_t* self)
{
    glassert_self();

    switch (self->obj_type) {
    case CORE_OBJECT_PCAP:
        return (core_object_t*)core_object_pcap_copy((core_object_pcap_t*)self);
    case CORE_OBJECT_ETHER:
        return (core_object_t*)core_object_ether_copy((core_object_ether_t*)self);
    case CORE_OBJECT_NULL:
        return (core_object_t*)core_object_null_copy((core_object_null_t*)self);
    case CORE_OBJECT_LOOP:
        return (core_object_t*)core_object_loop_copy((core_object_loop_t*)self);
    case CORE_OBJECT_LINUXSLL:
        return (core_object_t*)core_object_linuxsll_copy((core_object_linuxsll_t*)self);
    case CORE_OBJECT_IEEE802:
        return (core_object_t*)core_object_ieee802_copy((core_object_ieee802_t*)self);
    case CORE_OBJECT_GRE:
        return (core_object_t*)core_object_gre_copy((core_object_gre_t*)self);
    case CORE_OBJECT_IP:
        return (core_object_t*)core_object_ip_copy((core_object_ip_t*)self);
    case CORE_OBJECT_IP6:
        return (core_object_t*)core_object_ip6_copy((core_object_ip6_t*)self);
    case CORE_OBJECT_ICMP:
        return (core_object_t*)core_object_icmp_copy((core_object_icmp_t*)self);
    case CORE_OBJECT_ICMP6:
        return (core_object_t*)core_object_icmp6_copy((core_object_icmp6_t*)self);
    case CORE_OBJECT_UDP:
        return (core_object_t*)core_object_udp_copy((core_object_udp_t*)self);
    case CORE_OBJECT_TCP:
        return (core_object_t*)core_object_tcp_copy((core_object_tcp_t*)self);
    case CORE_OBJECT_PAYLOAD:
        return (core_object_t*)core_object_payload_copy((core_object_payload_t*)self);
    case CORE_OBJECT_DNS:
        return (core_object_t*)core_object_dns_copy((core_object_dns_t*)self);
    default:
        glfatal("unknown type %d", self->obj_type);
    }
    return 0;
}

void core_object_free(core_object_t* self)
{
    glassert_self();

    switch (self->obj_type) {
    case CORE_OBJECT_PCAP:
        core_object_pcap_free((core_object_pcap_t*)self);
        break;
    case CORE_OBJECT_ETHER:
        core_object_ether_free((core_object_ether_t*)self);
        break;
    case CORE_OBJECT_NULL:
        core_object_null_free((core_object_null_t*)self);
        break;
    case CORE_OBJECT_LOOP:
        core_object_loop_free((core_object_loop_t*)self);
        break;
    case CORE_OBJECT_LINUXSLL:
        core_object_linuxsll_free((core_object_linuxsll_t*)self);
        break;
    case CORE_OBJECT_IEEE802:
        core_object_ieee802_free((core_object_ieee802_t*)self);
        break;
    case CORE_OBJECT_GRE:
        core_object_gre_free((core_object_gre_t*)self);
        break;
    case CORE_OBJECT_IP:
        core_object_ip_free((core_object_ip_t*)self);
        break;
    case CORE_OBJECT_IP6:
        core_object_ip6_free((core_object_ip6_t*)self);
        break;
    case CORE_OBJECT_ICMP:
        core_object_icmp_free((core_object_icmp_t*)self);
        break;
    case CORE_OBJECT_ICMP6:
        core_object_icmp6_free((core_object_icmp6_t*)self);
        break;
    case CORE_OBJECT_UDP:
        core_object_udp_free((core_object_udp_t*)self);
        break;
    case CORE_OBJECT_TCP:
        core_object_tcp_free((core_object_tcp_t*)self);
        break;
    case CORE_OBJECT_PAYLOAD:
        core_object_payload_free((core_object_payload_t*)self);
        break;
    case CORE_OBJECT_DNS:
        core_object_dns_free((core_object_dns_t*)self);
        break;
    default:
        glfatal("unknown type %d", self->obj_type);
    }
}

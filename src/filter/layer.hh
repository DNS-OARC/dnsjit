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

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")
//lua:require("dnsjit.core.producer_h")
//lua:require("dnsjit.core.object.pcap_h")
//lua:require("dnsjit.core.object.null_h")
//lua:require("dnsjit.core.object.ether_h")
//lua:require("dnsjit.core.object.loop_h")
//lua:require("dnsjit.core.object.linuxsll_h")
//lua:require("dnsjit.core.object.ieee802_h")
//lua:require("dnsjit.core.object.ip_h")
//lua:require("dnsjit.core.object.ip6_h")
//lua:require("dnsjit.core.object.gre_h")
//lua:require("dnsjit.core.object.icmp_h")
//lua:require("dnsjit.core.object.icmp6_h")
//lua:require("dnsjit.core.object.udp_h")
//lua:require("dnsjit.core.object.tcp_h")
//lua:require("dnsjit.core.object.payload_h")

typedef struct filter_layer {
    core_log_t      _log;
    core_receiver_t recv;
    void*           ctx;

    core_producer_t prod;
    void*           prod_ctx;

    const core_object_t*   produced;
    core_object_null_t     null;
    core_object_ether_t    ether;
    core_object_loop_t     loop;
    core_object_linuxsll_t linuxsll;
    size_t                 n_ieee802;
    core_object_ieee802_t  ieee802[3]; // N_IEEE802
    core_object_ip_t       ip;
    core_object_ip6_t      ip6;
    core_object_gre_t      gre;
    core_object_icmp_t     icmp;
    core_object_icmp6_t    icmp6;
    core_object_udp_t      udp;
    core_object_tcp_t      tcp;
    core_object_payload_t  payload;
} filter_layer_t;

core_log_t* filter_layer_log();

void filter_layer_init(filter_layer_t* self);
void filter_layer_destroy(filter_layer_t* self);

core_receiver_t filter_layer_receiver();
core_producer_t filter_layer_producer(filter_layer_t* self);

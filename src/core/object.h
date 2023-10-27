/*
 * Copyright (c) 2018-2024 OARC, Inc.
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

#ifndef __dnsjit_core_object_h
#define __dnsjit_core_object_h

#define CORE_OBJECT_NONE 0
#define CORE_OBJECT_PCAP 1
/* link level objects */
#define CORE_OBJECT_ETHER 10
#define CORE_OBJECT_NULL 11
#define CORE_OBJECT_LOOP 12
#define CORE_OBJECT_LINUXSLL 13
#define CORE_OBJECT_IEEE802 14
#define CORE_OBJECT_GRE 15
/* protocol objects */
#define CORE_OBJECT_IP 20
#define CORE_OBJECT_IP6 21
#define CORE_OBJECT_ICMP 22
#define CORE_OBJECT_ICMP6 23
/* payload carrying objects */
#define CORE_OBJECT_UDP 30
#define CORE_OBJECT_TCP 31
/* payload */
#define CORE_OBJECT_PAYLOAD 40
/* service object(s) */
#define CORE_OBJECT_DNS 50

#include <stdint.h>
#include <dnsjit/core/object.hh>

#define CORE_OBJECT_INIT(type, prev) (core_object_t*)prev, type

#endif

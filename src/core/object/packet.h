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

#include "core/object.h"
#include "core/timespec.h"

#ifndef __dnsjit_core_object_packet_h
#define __dnsjit_core_object_packet_h

#include <stddef.h>

#include "core/object/packet.hh"

#define CORE_OBJECT_PACKET_INIT(prev)             \
    {                                             \
        CORE_OBJECT_PACKET, (core_object_t*)prev, \
            0, 0, 0,                              \
            0, 0, 0,                              \
            0, 0,                                 \
            0, 0, CORE_TIMESPEC_INIT,             \
            0, 0                                  \
    }

#endif

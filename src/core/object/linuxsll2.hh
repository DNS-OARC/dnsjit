/*
 * Copyright (c) 2018-2025 OARC, Inc.
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

// lua:require("dnsjit.core.object_h")

typedef struct core_object_linuxsll2 {
    const core_object_t* obj_prev;
    int32_t              obj_type;

    uint16_t protocol_type;
    uint16_t reserved;
    uint32_t interface_index;
    uint16_t arphrd_type;
    uint8_t  packet_type;
    uint8_t  link_layer_address_length;
    uint8_t  link_layer_address[8];
} core_object_linuxsll2_t;

core_object_linuxsll2_t* core_object_linuxsll2_copy(const core_object_linuxsll2_t* self);
void                     core_object_linuxsll2_free(core_object_linuxsll2_t* self);

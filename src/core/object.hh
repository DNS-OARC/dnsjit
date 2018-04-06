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
 * You should have objectd a copy of the GNU General Public License
 * along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.
 */

typedef struct core_object core_object_t;

typedef enum core_object_reference {
    CORE_OBJECT_INCREF,
    CORE_OBJECT_DECREF
} core_object_reference_t;

typedef void (*core_object_refcall_t)(core_object_t* obj, core_object_reference_t ref);

struct core_object {
    unsigned short        obj_type;
    const core_object_t*  obj_prev;
    core_object_refcall_t obj_ref;
    void*                 obj_refctx;
};

core_object_t* core_object_copy(const core_object_t* obj);

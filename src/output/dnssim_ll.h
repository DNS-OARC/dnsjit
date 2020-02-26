/*
 * Copyright (c) 2019-2020, CZ.NIC, z.s.p.o.
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

#ifndef __dnsjit_output_dnssim_ll_h
#define __dnsjit_output_dnssim_ll_h

#include "core/assert.h"

/* Utility macros for linked list structures.
 *
 * - "list" is the pointer to the first node of the linked list
 * - "list" can be NULL if there are no nodes
 * - every node has "next", which points to the next node (can be NULL)
 */


/* Append a node to the list.
 *
 * Only a single node can be appended - node->next must be NULL.
 */
#define _ll_append(list, node) \
    { \
        glassert((node)->next == NULL, "node->next must be null when appending"); \
        if ((list) == NULL) \
            (list) = (node); \
        else if ((node) != NULL) \
        { \
            typeof(list) _current = (list); \
            while (_current->next != NULL) \
                _current = _current->next; \
            _current->next = node; \
        } \
    }

/* Remove a node from the list.
 *
 * In strict mode, the node must be present in the list.
 */
#define _ll_remove_template(list, node, strict) \
    { \
        if (strict) \
            glassert((list), "list can't be null when removing nodes"); \
        if ((list) != NULL && (node) != NULL) { \
            if ((list) == (node)) { \
                (list) = (node)->next; \
                (node)->next = NULL; \
            } else { \
                typeof(list) _current = (list); \
                while (_current != NULL && _current->next != (node)) { \
                    if (strict) \
                        glassert((_current->next), "list doesn't contain the node to be removed"); \
                    _current = _current->next; \
                } \
                if (_current != NULL) { \
                    _current->next = (node)->next; \
                    (node)->next = NULL; \
                } \
            } \
        } \
    }

/* Remove a node from the list. */
#define _ll_remove(list, node) _ll_remove_template((list), (node), true)

/* Remove a node from the list if it's present. */
#define _ll_try_remove(list, node) _ll_remove_template((list), (node), false)

#endif

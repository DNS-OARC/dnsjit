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

#include "core/log.h"
#include "core/timespec.h"
#include "omg-dns/omg_dns.h"

#ifndef __dnsjit_core_query_h
#define __dnsjit_core_query_h

#include <netinet/in.h>
#include <sys/types.h>

#include "core/query.hh"

#define core_query_raw(query) (query->raw ? query->raw : query->small)

int core_query_set_src(core_query_t* self, int af, const void* addr, size_t len);
int core_query_set_dst(core_query_t* self, int af, const void* addr, size_t len);
int core_query_set_parsed_header(core_query_t* self, omg_dns_t dns);

#endif

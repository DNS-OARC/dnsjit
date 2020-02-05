/*
 * Copyright (c) 2019, CZ.NIC, z.s.p.o.
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

#include "filter/dnssim.h"
#include "core/assert.h"

static core_log_t     _log      = LOG_T_INIT("filter.dnssim");
static filter_dnssim_t _defaults = {
    LOG_T_INIT_OBJ("filter.dnssim"),
    0
};

core_log_t* filter_dnssim_log()
{
    return &_log;
}

void filter_dnssim_init(filter_dnssim_t* self)
{
    mlassert_self();

    *self = _defaults;
}

void filter_dnssim_destroy(filter_dnssim_t* self)
{
    mlassert_self();
}

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
#include "core/receiver.h"

#ifndef __dnsjit_core_channel_h
#define __dnsjit_core_channel_h

#if defined(__GNUC__) || defined(__SUNPRO_C)
#include "gcc/ck_cc.h"
#ifdef CK_CC_RESTRICT
#undef CK_CC_RESTRICT
#define CK_CC_RESTRICT __restrict__
#endif
#endif

#include <ck_ring.h>
#include <ck_pr.h>

#include "core/channel.hh"

#endif

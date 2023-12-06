/*
 * Copyright (c) 2018-2023, OARC, Inc.
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

#include "globals.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

void dnsjit_globals(lua_State* L)
{
#ifdef PACKAGE_VERSION
    lua_pushstring(L, PACKAGE_VERSION);
#elif defined(VERSION)
    lua_pushstring(L, VERSION);
#else
#error "No PACKAGE_VERSION or VERSION defined"
#endif
    lua_setglobal(L, "DNSJIT_VERSION");

    lua_pushinteger(L, PACKAGE_MAJOR_VERSION);
    lua_setglobal(L, "DNSJIT_MAJOR_VERSION");
    lua_pushinteger(L, PACKAGE_MINOR_VERSION);
    lua_setglobal(L, "DNSJIT_MINOR_VERSION");
    lua_pushinteger(L, PACKAGE_PATCH_VERSION);
    lua_setglobal(L, "DNSJIT_PATCH_VERSION");

#ifdef PACKAGE_BUGREPORT
    lua_pushstring(L, PACKAGE_BUGREPORT);
#else
    lua_pushstring(L, "none");
#endif
    lua_setglobal(L, "DNSJIT_BUGREPORT");

#ifdef PACKAGE_URL
    lua_pushstring(L, PACKAGE_URL);
#else
    lua_pushstring(L, "none");
#endif
    lua_setglobal(L, "DNSJIT_URL");
}

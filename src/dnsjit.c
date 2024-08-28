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

#include "config.h"

#include "globals.h"
#include "core/log.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <stdio.h>

int main(int argc, char* argv[])
{
    lua_State* L;
    int        n, err;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.lua> ...\n", argv[0]);
        exit(1);
    }

    L = luaL_newstate();
    luaL_openlibs(L);
    dnsjit_globals(L);

    lua_createtable(L, argc, 0);
    for (n = 0; n < argc; n++) {
        lua_pushstring(L, argv[n]);
        lua_rawseti(L, -2, n);
    }
    lua_setglobal(L, "arg");
    if ((err = luaL_loadfile(L, argv[1]))) {
        switch (err) {
        case LUA_ERRSYNTAX:
            glcritical("%s: syntax error during pre-compilation", argv[1]);
            break;
        case LUA_ERRMEM:
            glcritical("%s: memory allocation error", argv[1]);
            break;
        case LUA_ERRFILE:
            glcritical("%s: cannot open/read file", argv[1]);
            break;
        default:
            glcritical("%s: unknown error %d", argv[1], err);
            break;
        }
        return 1;
    }
    if (lua_pcall(L, 0, 0, 0)) {
        glcritical("%s: %s", argv[1], lua_tostring(L, -1));
        lua_pop(L, 1);
        return 1;
    }
    lua_close(L);

    return 0;
}

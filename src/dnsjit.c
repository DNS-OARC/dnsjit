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

#include "config.h"

#include "globals.h"
#include "core/log.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>

static void* _sighthr(void* arg)
{
    sigset_t* set = (sigset_t*)arg;
    int       sig = 0, err;

    if ((err = sigwait(set, &sig))) {
        gldebug("sigwait %d", err);
    }
    glfatal("signal %d", sig);

    return 0;
}

int main(int argc, char* argv[])
{
    lua_State* L;
    int        n, err;
    sigset_t   set;
    pthread_t  sighthr;

#ifdef PACKAGE_NAME
    fprintf(stderr, "<< " PACKAGE_NAME
#ifdef PACKAGE_VERSION
                    " v" PACKAGE_VERSION
#endif
#ifdef PACKAGE_URL
                    " " PACKAGE_URL
#endif
                    " >>\n");
#endif

    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.lua> ...\n", argv[0]);
        exit(1);
    }

    sigfillset(&set);
    if ((err = pthread_sigmask(SIG_BLOCK, &set, 0))) {
        glfatal("Unable to set blocked signals with pthread_sigmask()");
        return 2;
    }

    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGINT);

    if ((err = pthread_create(&sighthr, 0, _sighthr, &set))) {
        glfatal("Unable to start signal thread with pthread_create()");
        return 2;
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

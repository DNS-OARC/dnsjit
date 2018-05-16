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

#include "output/respdiff.h"
#include "core/object/payload.h"

#ifdef HAVE_LMDB_H
#include <lmdb.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

static core_log_t        _log      = LOG_T_INIT("output.respdiff");
static output_respdiff_t _defaults = {
    LOG_T_INIT_OBJ("output.respdiff"),
    0, 0, 0, 0, 0, 0
};

core_log_t* output_respdiff_log()
{
    return &_log;
}

int output_respdiff_init(output_respdiff_t* self, const char* path)
{
    if (!self || !path) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

#ifdef HAVE_LMDB_H
    if (mkdir(path, 0775) && errno != EEXIST) {
        lwarning("mkdir(%s) failed (%d)", path, errno);
        return 1;
    }
    ldebug("mkdir");

    if (mdb_env_create((MDB_env**)&self->env)) {
        lwarning("mdb_env_create failed");
        return 1;
    }
    ldebug("mdb_env_create");

    if (mdb_env_set_maxdbs((MDB_env*)self->env, 2)) {
        lwarning("mdb_env_set_maxdbs failed");
        return 1;
    }
    ldebug("mdb_env_set_maxdbs");

    if (mdb_env_open((MDB_env*)self->env, path, 0, 0664)) {
        lwarning("mdb_env_open(%s) failed", path);
        return 1;
    }
    ldebug("mdb_env_open");

    if (mdb_txn_begin((MDB_env*)self->env, 0, 0, (MDB_txn**)&self->txn)) {
        lwarning("mdb_txn_begin failed for queries");
        return 1;
    }
    ldebug("mdb_txn_begin");

    if (!(self->qdb = calloc(1, sizeof(MDB_dbi)))
        || mdb_dbi_open((MDB_txn*)self->txn, "queries", MDB_CREATE, (MDB_dbi*)self->qdb)) {
        lwarning("mdb_dbi_open failed for queries");
        return 1;
    }
    ldebug("mdb_dbi_open");

    if (!(self->rdb = calloc(1, sizeof(MDB_dbi)))
        || mdb_dbi_open((MDB_txn*)self->txn, "dnsjit", MDB_CREATE, (MDB_dbi*)self->rdb)) {
        lwarning("mdb_dbi_open failed for responses");
        return 1;
    }
    ldebug("mdb_dbi_open");

    return 0;
#else
    return 1;
#endif
}

int output_respdiff_destroy(output_respdiff_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy");

#ifdef HAVE_LMDB_H
    if (self->env) {
        mdb_env_close((MDB_env*)self->env);
    }
    free(self->qdb);
    free(self->rdb);
#endif

    return 0;
}

int output_respdiff_commit(output_respdiff_t* self)
{
#ifdef HAVE_LMDB_H
    if (!self) {
        return 1;
    }

    if (self->txn) {
        if (mdb_txn_commit((MDB_txn*)self->txn)) {
            return 1;
        }
        ldebug("commit ok");
        self->txn = 0;
    }

    return 0;
#else
    return 1;
#endif
}

#ifdef HAVE_LMDB_H
static int _receive(void* ctx, const core_object_t* obj)
{
    output_respdiff_t*           self = (output_respdiff_t*)ctx;
    const core_object_payload_t *query, *original, *response;
    MDB_val                      k, v;

    if (!self || !self->txn) {
        return 1;
    }

    if (!obj || obj->obj_type != CORE_OBJECT_PAYLOAD) {
        return 1;
    }
    query = (core_object_payload_t*)obj;
    if (!query->obj_prev || query->obj_prev->obj_type != CORE_OBJECT_PAYLOAD) {
        return 1;
    }
    original = (core_object_payload_t*)query->obj_prev;
    if (!original->obj_prev || original->obj_prev->obj_type != CORE_OBJECT_PAYLOAD) {
        return 1;
    }
    response = (core_object_payload_t*)original->obj_prev;

    ldebug("query %p %u", query->payload, query->len);
    ldebug("original %p %u", original->payload, original->len);
    ldebug("response %p %u", response->payload, response->len);

    self->count++;

    k.mv_size = sizeof(self->id);
    k.mv_data = (void*)&self->id;
    v.mv_size = query->len;
    v.mv_data = (void*)query->payload;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->qdb), &k, &v, 0)) {
        lwarning("mdb_put query failed");
    }

    self->id++;
    v.mv_size = original->len;
    v.mv_data = (void*)original->payload;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->rdb), &k, &v, 0)) {
        lwarning("mdb_put original failed");
    }

    self->id++;
    v.mv_size = response->len;
    v.mv_data = (void*)response->payload;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->rdb), &k, &v, 0)) {
        lwarning("mdb_put response failed");
    }

    self->id += (0x100 - 2);

    return 0;
}

core_receiver_t output_respdiff_receiver()
{
    return _receive;
}
#else
core_receiver_t output_respdiff_receiver()
{
    return 0;
}
#endif

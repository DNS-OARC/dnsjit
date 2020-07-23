/*
 * Copyright (c) 2018-2020, OARC, Inc.
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
#include "core/assert.h"
#include "core/object/payload.h"

#ifdef HAVE_LMDB_H
#include <lmdb.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

static core_log_t        _log      = LOG_T_INIT("output.respdiff");
static output_respdiff_t _defaults = {
    LOG_T_INIT_OBJ("output.respdiff"),
    0, 0, 0, 0, 0, 0
};

core_log_t* output_respdiff_log()
{
    return &_log;
}

void output_respdiff_init(output_respdiff_t* self, const char* path, size_t mapsize)
{
    mlassert_self();

    if (!path) {
        lfatal("path is nil");
    }

    *self = _defaults;

#ifdef HAVE_LMDB_H
    if (mkdir(path, 0775) && errno != EEXIST) {
        lfatal("mkdir(%s) error %s", path, core_log_errstr(errno));
    }
    if (mdb_env_create((MDB_env**)&self->env)) {
        lfatal("mdb_env_create failed");
    }
    if (mdb_env_set_mapsize((MDB_env*)self->env, mapsize)) {
        lfatal("mdb_env_set_mapsize(%lu) failed", mapsize);
    }
    if (mdb_env_set_maxdbs((MDB_env*)self->env, 3)) {
        lfatal("mdb_env_set_maxdbs failed");
    }
    if (mdb_env_open((MDB_env*)self->env, path, 0, 0664)) {
        lfatal("mdb_env_open(%s) failed", path);
    }
    if (mdb_txn_begin((MDB_env*)self->env, 0, 0, (MDB_txn**)&self->txn)) {
        lfatal("mdb_txn_begin failed for queries");
    }
    lfatal_oom(self->qdb = calloc(1, sizeof(MDB_dbi)));
    if (mdb_dbi_open((MDB_txn*)self->txn, "queries", MDB_CREATE, (MDB_dbi*)self->qdb)) {
        lfatal("mdb_dbi_open failed for queries");
    }
    lfatal_oom(self->rdb = calloc(1, sizeof(MDB_dbi)));
    if (mdb_dbi_open((MDB_txn*)self->txn, "answers", MDB_CREATE, (MDB_dbi*)self->rdb)) {
        lfatal("mdb_dbi_open failed for responses");
    }
    lfatal_oom(self->meta = calloc(1, sizeof(MDB_dbi)));
    if (mdb_dbi_open((MDB_txn*)self->txn, "meta", MDB_CREATE, (MDB_dbi*)self->meta)) {
        lfatal("mdb_dbi_open failed for meta");
    }
#endif
}

void output_respdiff_destroy(output_respdiff_t* self)
{
    mlassert_self();

#ifdef HAVE_LMDB_H
    if (self->env) {
        mdb_env_close((MDB_env*)self->env);
    }
    free(self->qdb);
    free(self->rdb);
    free(self->meta);
#endif
}

#ifdef HAVE_LMDB_H
static const char* _meta_version     = "version";
static const char* _meta_version_val = "2018-05-21";
static const char* _meta_servers     = "servers";
static const char* _meta_name0       = "name0";
static const char* _meta_name1       = "name1";
static const char* _meta_start_time  = "start_time";
static const char* _meta_end_time    = "end_time";
#endif

void output_respdiff_commit(output_respdiff_t* self, const char* origname, const char* recvname, uint64_t start_time, uint64_t end_time)
{
#ifdef HAVE_LMDB_H
    MDB_val  k, v;
    uint32_t i;
    int      err;
    mlassert_self();
    lassert(origname, "origname is nil");
    lassert(recvname, "recvname is nil");

    k.mv_size = strlen(_meta_version);
    k.mv_data = (void*)_meta_version;
    v.mv_size = strlen(_meta_version_val);
    v.mv_data = (void*)_meta_version_val;
    if ((err = mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0))) {
        if (err == MDB_MAP_FULL) {
            lfatal("mdb_put meta.version failed, database is full");
        } else {
            lfatal("mdb_put meta.version failed (%d)", err);
        }
    }

    k.mv_size = strlen(_meta_servers);
    k.mv_data = (void*)_meta_servers;
    i         = 2;
    v.mv_size = 4;
    v.mv_data = (void*)&i;
    if ((err = mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0))) {
        if (err == MDB_MAP_FULL) {
            lfatal("mdb_put meta.servers failed, database is full");
        } else {
            lfatal("mdb_put meta.servers failed (%d)", err);
        }
    }

    k.mv_size = strlen(_meta_name0);
    k.mv_data = (void*)_meta_name0;
    v.mv_size = strlen(origname);
    v.mv_data = (void*)origname;
    if ((err = mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0))) {
        if (err == MDB_MAP_FULL) {
            lfatal("mdb_put meta.name0 failed, database is full");
        } else {
            lfatal("mdb_put meta.name0 failed (%d)", err);
        }
    }

    k.mv_size = strlen(_meta_name1);
    k.mv_data = (void*)_meta_name1;
    v.mv_size = strlen(recvname);
    v.mv_data = (void*)recvname;
    if ((err = mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0))) {
        if (err == MDB_MAP_FULL) {
            lfatal("mdb_put meta.name1 failed, database is full");
        } else {
            lfatal("mdb_put meta.name1 failed (%d)", err);
        }
    }

    k.mv_size = strlen(_meta_start_time);
    k.mv_data = (void*)_meta_start_time;
    i         = start_time;
    v.mv_size = 4;
    v.mv_data = (void*)&i;
    if ((err = mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0))) {
        if (err == MDB_MAP_FULL) {
            lfatal("mdb_put meta.start_time failed, database is full");
        } else {
            lfatal("mdb_put meta.start_time failed (%d)", err);
        }
    }

    k.mv_size = strlen(_meta_end_time);
    k.mv_data = (void*)_meta_end_time;
    i         = end_time;
    v.mv_size = 4;
    v.mv_data = (void*)&i;
    if ((err = mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0))) {
        if (err == MDB_MAP_FULL) {
            lfatal("mdb_put meta.end_time failed, database is full");
        } else {
            lfatal("mdb_put meta.end_time failed (%d)", err);
        }
    }

    if (self->txn) {
        if (mdb_txn_commit((MDB_txn*)self->txn)) {
            lfatal("mdb_txn_commit failed");
        }
        self->txn = 0;
    }
#endif
}

#ifdef HAVE_LMDB_H
static void _receive(output_respdiff_t* self, const core_object_t* obj)
{
    const core_object_payload_t *query, *original, *response;
    MDB_val                      k, v;
    uint8_t                      responses[132096];
    uint32_t                     msec;
    uint16_t                     dnslen;
    int                          err;
    mlassert_self();

    if (!obj || obj->obj_type != CORE_OBJECT_PAYLOAD) {
        lfatal("invalid first object");
    }
    query = (core_object_payload_t*)obj;

    if (!query->obj_prev || query->obj_prev->obj_type != CORE_OBJECT_PAYLOAD) {
        lfatal("invalid second object");
    }
    original = (core_object_payload_t*)query->obj_prev;

    response = (core_object_payload_t*)original->obj_prev;
    if (response && response->obj_type != CORE_OBJECT_PAYLOAD) {
        lfatal("invalid third object");
    }

    if (12 + original->len + (response ? response->len : 0) > sizeof(responses)) {
        lfatal("not enough buffer space for responses");
    }

    self->count++;

    k.mv_size = sizeof(self->id);
    k.mv_data = (void*)&self->id;
    v.mv_size = query->len;
    v.mv_data = (void*)query->payload;
    if ((err = mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->qdb), &k, &v, 0))) {
        if (err == MDB_MAP_FULL) {
            lfatal("mdb_put query failed, database is full");
        } else {
            lfatal("mdb_put query failed (%d)", err);
        }
    }

    msec = 1; // TODO
    memcpy(responses, &msec, 4);
    dnslen = original->len;
    memcpy(&responses[4], &dnslen, 2);
    memcpy(&responses[6], original->payload, original->len);
    if (response) {
        memcpy(&responses[6 + original->len], &msec, 4);
        dnslen = response->len;
        memcpy(&responses[10 + original->len], &dnslen, 2);
        memcpy(&responses[12 + original->len], response->payload, response->len);
    } else {
        msec = 0xffffffff;
        memcpy(&responses[6 + original->len], &msec, 4);
        dnslen = 0;
        memcpy(&responses[10 + original->len], &dnslen, 2);
    }

    v.mv_size = 12 + original->len + (response ? response->len : 0);
    v.mv_data = (void*)responses;
    if ((err = mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->rdb), &k, &v, 0))) {
        if (err == MDB_MAP_FULL) {
            lfatal("mdb_put answers failed, database is full");
        } else {
            lfatal("mdb_put answers failed (%d)", err);
        }
    }

    self->id++;
}

core_receiver_t output_respdiff_receiver(output_respdiff_t* self)
{
    mlassert_self();

    if (!self->txn) {
        lfatal("no LMDB opened");
    }

    return (core_receiver_t)_receive;
}
#else
core_receiver_t output_respdiff_receiver(output_respdiff_t* self)
{
    mlassert_self();
    lfatal("no LMDB support");
    return 0;
}
#endif

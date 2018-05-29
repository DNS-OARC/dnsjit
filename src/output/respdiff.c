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

    if (mdb_env_set_maxdbs((MDB_env*)self->env, 3)) {
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
        || mdb_dbi_open((MDB_txn*)self->txn, "answers", MDB_CREATE, (MDB_dbi*)self->rdb)) {
        lwarning("mdb_dbi_open failed for responses");
        return 1;
    }
    ldebug("mdb_dbi_open");

    if (!(self->meta = calloc(1, sizeof(MDB_dbi)))
        || mdb_dbi_open((MDB_txn*)self->txn, "meta", MDB_CREATE, (MDB_dbi*)self->meta)) {
        lwarning("mdb_dbi_open failed for meta");
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
    free(self->meta);
#endif

    return 0;
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

int output_respdiff_commit(output_respdiff_t* self, const char* origname, const char* recvname, uint64_t start_time, uint64_t end_time)
{
#ifdef HAVE_LMDB_H
    MDB_val  k, v;
    uint32_t i;

    if (!self || !origname || !recvname) {
        return 1;
    }

    k.mv_size = strlen(_meta_version);
    k.mv_data = (void*)_meta_version;
    v.mv_size = strlen(_meta_version_val);
    v.mv_data = (void*)_meta_version_val;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0)) {
        lwarning("mdb_put meta.version failed");
        return 1;
    }

    k.mv_size = strlen(_meta_servers);
    k.mv_data = (void*)_meta_servers;
    i         = 2;
    v.mv_size = 4;
    v.mv_data = (void*)&i;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0)) {
        lwarning("mdb_put meta.servers failed");
        return 1;
    }

    k.mv_size = strlen(_meta_name0);
    k.mv_data = (void*)_meta_name0;
    v.mv_size = strlen(origname);
    v.mv_data = (void*)origname;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0)) {
        lwarning("mdb_put meta.name0 failed");
        return 1;
    }

    k.mv_size = strlen(_meta_name1);
    k.mv_data = (void*)_meta_name1;
    v.mv_size = strlen(recvname);
    v.mv_data = (void*)recvname;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0)) {
        lwarning("mdb_put meta.name1 failed");
        return 1;
    }

    k.mv_size = strlen(_meta_start_time);
    k.mv_data = (void*)_meta_start_time;
    i         = start_time;
    v.mv_size = 4;
    v.mv_data = (void*)&i;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0)) {
        lwarning("mdb_put meta.start_time failed");
        return 1;
    }

    k.mv_size = strlen(_meta_end_time);
    k.mv_data = (void*)_meta_end_time;
    i         = end_time;
    v.mv_size = 4;
    v.mv_data = (void*)&i;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->meta), &k, &v, 0)) {
        lwarning("mdb_put meta.end_time failed");
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
    uint8_t                      responses[132096];
    uint32_t                     msec;
    uint16_t                     dnslen;

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

    if (12 + original->len + response->len > sizeof(responses)) {
        lcritical("mdb_put failed, not enough space");
        return 1;
    }

    self->count++;

    k.mv_size = sizeof(self->id);
    k.mv_data = (void*)&self->id;
    v.mv_size = query->len;
    v.mv_data = (void*)query->payload;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->qdb), &k, &v, 0)) {
        lwarning("mdb_put query failed");
        return 1;
    }

    msec = 1; // TODO
    memcpy(responses, &msec, 4);
    dnslen = original->len;
    memcpy(&responses[4], &dnslen, 2);
    memcpy(&responses[6], original->payload, original->len);
    memcpy(&responses[6 + original->len], &msec, 4);
    dnslen = response->len;
    memcpy(&responses[10 + original->len], &dnslen, 2);
    memcpy(&responses[12 + original->len], response->payload, response->len);

    v.mv_size = 12 + original->len + response->len;
    v.mv_data = (void*)responses;
    if (mdb_put((MDB_txn*)self->txn, (MDB_dbi) * ((MDB_dbi*)self->rdb), &k, &v, 0)) {
        lwarning("mdb_put answers failed");
        return 1;
    }

    self->id++;

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

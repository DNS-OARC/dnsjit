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

#include "filter/thread.h"

static core_log_t      _log      = LOG_T_INIT("filter.thread");
static filter_thread_t _defaults = {
    LOG_T_INIT_OBJ("filter.thread"),
    0,
    0, 0, 0,
    0
};

core_log_t* filter_thread_log()
{
    return &_log;
}

static void* _thread_writers(void* user)
{
    filter_thread_recv_t* recv = (filter_thread_recv_t*)user;
    filter_thread_t*      self = (filter_thread_t*)recv->self;
    size_t                ends = 0, at = 0;
    core_object_t*        obj = 0;

    while (ends < self->works) {
        filter_thread_work_t* w = &self->work[at];
        pthread_mutex_lock(&w->mutex);
        if (!w->end) {
            while (!w->end && !w->obj) {
                if (!w->writers) {
                    pthread_mutex_unlock(&w->mutex);
                    at++;
                    if (at == self->works)
                        at = 0;
                    w      = &self->work[at];
                    pthread_mutex_lock(&w->mutex);
                    continue;
                }
                pthread_cond_wait(&w->read, &w->mutex);
            }
        }
        if (w->obj) {
            obj    = w->obj;
            w->obj = 0;
            pthread_cond_signal(&w->write);
        }
        if (w->end) {
            ends++;
        }
        pthread_mutex_unlock(&w->mutex);

        if (obj) {
            recv->recv(recv->ctx, obj);
            core_object_free(obj);
            obj = 0;
        }

        at++;
        if (at == self->works)
            at = 0;
    }

    return 0;
}

static void* _thread(void* user)
{
    filter_thread_recv_t* recv = (filter_thread_recv_t*)user;
    filter_thread_t*      self = (filter_thread_t*)recv->self;
    size_t                ends = 0, at = 0;
    core_object_t*        obj = 0;

    while (ends < self->works) {
        filter_thread_work_t* w = &self->work[at];
        pthread_mutex_lock(&w->mutex);
        if (!w->end) {
            while (!w->end && !w->obj) {
                pthread_cond_wait(&w->read, &w->mutex);
            }
        }
        if (w->obj) {
            obj    = w->obj;
            w->obj = 0;
            pthread_cond_signal(&w->write);
        }
        if (w->end) {
            ends++;
        }
        pthread_mutex_unlock(&w->mutex);

        if (obj) {
            recv->recv(recv->ctx, obj);
            core_object_free(obj);
            obj = 0;
        }

        at++;
        if (at == self->works)
            at = 0;
    }

    return 0;
}

int filter_thread_init(filter_thread_t* self, size_t queue_size)
{
    filter_thread_work_t defwork = { 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0 };
    size_t               n;

    if (!self || !queue_size) {
        return 1;
    }

    *self = _defaults;

    ldebug("init");

    self->works = queue_size;

    if (!(self->work = malloc(sizeof(filter_thread_work_t) * self->works))) {
        return 1;
    }
    for (n = 0; n < self->works; n++) {
        self->work[n] = defwork;
    }
    self->work[0].writers = 1;

    return 0;
}

int filter_thread_destroy(filter_thread_t* self)
{
    filter_thread_recv_t* r;

    if (!self) {
        return 1;
    }

    ldebug("destroy");

    free(self->work);
    while ((r = self->recv)) {
        self->recv = r->next;
        free(r);
    }

    return 0;
}

int filter_thread_add(filter_thread_t* self, core_receiver_t recv, void* ctx)
{
    filter_thread_recv_t* r;

    if (!self) {
        return 1;
    }

    if (!(r = malloc(sizeof(filter_thread_recv_t)))) {
        return 1;
    }

    r->self    = self;
    r->next    = self->recv;
    r->recv    = recv;
    r->ctx     = ctx;
    r->tid     = 0;
    self->recv = r;

    return 0;
}

int filter_thread_start(filter_thread_t* self)
{
    filter_thread_recv_t* r;

    if (!self || !self->work || !self->recv) {
        return 1;
    }

    for (r = self->recv; r; r = r->next) {
        if (self->use_writers) {
            if (pthread_create(&r->tid, 0, _thread_writers, (void*)r)) {
                return 2;
            }
            continue;
        }
        if (pthread_create(&r->tid, 0, _thread, (void*)r)) {
            return 2;
        }
    }

    ldebug("start");

    return 0;
}

int filter_thread_stop(filter_thread_t* self)
{
    filter_thread_recv_t* r;
    size_t                n;

    if (!self) {
        return 1;
    }

    for (n = 0; n < self->works; n++) {
        filter_thread_work_t* w = &self->work[n];
        pthread_mutex_lock(&w->mutex);
        w->end = 1;
        pthread_cond_broadcast(&w->read);
        pthread_mutex_unlock(&w->mutex);
    }
    for (r = self->recv; r; r = r->next) {
        pthread_join(r->tid, 0);
    }

    ldebug("stop");

    return 0;
}

static int _receive_writers(void* ctx, const core_object_t* obj)
{
    filter_thread_t*      self = (filter_thread_t*)ctx;
    core_object_t*        copy = core_object_copy(obj);
    filter_thread_work_t* w;

    if (!self || !copy || !self->recv) {
        return 1;
    }

    w = &self->work[self->at];
    pthread_mutex_lock(&w->mutex);
    w->writers = 1;
    while (w->obj) {
        pthread_cond_wait(&w->write, &w->mutex);
    }
    w->writers = 0;
    w->obj     = copy;

    self->at++;
    if (self->at == self->works)
        self->at = 0;

    pthread_mutex_lock(&self->work[self->at].mutex);
    self->work[self->at].writers = 1;
    pthread_mutex_unlock(&self->work[self->at].mutex);

    pthread_cond_broadcast(&w->read);
    pthread_mutex_unlock(&w->mutex);

    return 0;
}

static int _receive(void* ctx, const core_object_t* obj)
{
    filter_thread_t*      self = (filter_thread_t*)ctx;
    core_object_t*        copy = core_object_copy(obj);
    filter_thread_work_t* w;

    if (!self || !copy || !self->recv) {
        return 1;
    }

    w = &self->work[self->at];
    pthread_mutex_lock(&w->mutex);
    while (w->obj) {
        pthread_cond_wait(&w->write, &w->mutex);
    }
    w->obj = copy;
    pthread_cond_signal(&w->read);
    pthread_mutex_unlock(&w->mutex);

    self->at++;
    if (self->at == self->works)
        self->at = 0;

    return 0;
}

core_receiver_t filter_thread_receiver(filter_thread_t* self)
{
    if (self && self->use_writers) {
        return _receive_writers;
    }
    return _receive;
}

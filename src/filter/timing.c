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

#include "filter/timing.h"
#include "core/timespec.h"
#include "core/object/packet.h"

#include <time.h>
#include <sys/time.h>
#include <errno.h>

#define N1e9 1000000000

typedef struct _filter_timing {
    filter_timing_t pub;

    struct timespec diff;
    core_timespec_t last_pkthdr_ts;
    struct timespec last_ts;
    int (*timing_callback)(filter_timing_t*, const core_object_packet_t*, const core_object_t*);
    struct timespec mod_ts;
} _filter_timing_t;

static core_log_t      _log      = LOG_T_INIT("filter.timing");
static filter_timing_t _defaults = {
    LOG_T_INIT_OBJ("filter.timing"), 0, 0,
    TIMING_MODE_KEEP, 0, 0, 0.0,
};

core_log_t* filter_timing_log()
{
    return &_log;
}

static int _keep(filter_timing_t* self, const core_object_packet_t* pkt, const core_object_t* obj)
{
    _filter_timing_t* _self = (_filter_timing_t*)self;
#if HAVE_CLOCK_NANOSLEEP
    struct timespec to = {
        _self->diff.tv_sec + pkt->ts.sec,
        _self->diff.tv_nsec + pkt->ts.nsec
    };
    int ret = EINTR;

    if (to.tv_nsec >= N1e9) {
        to.tv_sec += 1;
        to.tv_nsec -= N1e9;
    } else if (to.tv_nsec < 0) {
        to.tv_sec -= 1;
        to.tv_nsec += N1e9;
    }

    while (ret) {
        ldebug("keep mode, sleep to %ld.%ld", to.tv_sec, to.tv_nsec);
        ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &to, 0);
        if (ret && ret != EINTR) {
            lfatal("clock_nanosleep(%ld.%ld) %d", to.tv_sec, to.tv_nsec, ret);
        }
    }
#elif HAVE_NANOSLEEP
    struct timespec diff = {
        pkt->ts.sec - _self->last_pkthdr_ts.sec,
        pkt->ts.nsec - _self->last_pkthdr_ts.nsec
    };
    int ret = EINTR;

    if (diff.tv_nsec >= N1e9) {
        diff.tv_sec += 1;
        diff.tv_nsec -= N1e9;
    } else if (diff.tv_nsec < 0) {
        diff.tv_sec -= 1;
        diff.tv_nsec += N1e9;
    }

    if (diff.tv_sec > -1 && diff.tv_nsec > -1) {
        while (ret) {
            ldebug("keep mode, sleep for %ld.%ld", diff.tv_sec, diff.tv_nsec);
            if ((ret = nanosleep(&diff, &diff))) {
                ret = errno;
                if (ret != EINTR) {
                    lfatal("nanosleep(%ld.%ld) %d", diff.tv_sec, diff.tv_nsec, ret);
                }
            }
        }
    }

    _self->last_pkthdr_ts = pkt->ts;
#endif

    self->recv(self->ctx, obj);

    return 0;
}

static int _increase(filter_timing_t* self, const core_object_packet_t* pkt, const core_object_t* obj)
{
    _filter_timing_t* _self = (_filter_timing_t*)self;
    struct timespec   diff  = {
        pkt->ts.sec - _self->last_pkthdr_ts.sec,
        pkt->ts.nsec - _self->last_pkthdr_ts.nsec
    };
    int ret = EINTR;

    if (diff.tv_nsec >= N1e9) {
        diff.tv_sec += 1;
        diff.tv_nsec -= N1e9;
    } else if (diff.tv_nsec < 0) {
        diff.tv_sec -= 1;
        diff.tv_nsec += N1e9;
    }

    diff.tv_sec += _self->mod_ts.tv_sec;
    diff.tv_nsec += _self->mod_ts.tv_nsec;
    if (diff.tv_nsec >= N1e9) {
        diff.tv_sec += 1;
        diff.tv_nsec -= N1e9;
    }

    if (diff.tv_sec > -1 && diff.tv_nsec > -1) {
#if HAVE_CLOCK_NANOSLEEP
        struct timespec to = {
            _self->last_ts.tv_sec + diff.tv_sec,
            _self->last_ts.tv_nsec + diff.tv_nsec
        };

        if (to.tv_nsec >= N1e9) {
            to.tv_sec += 1;
            to.tv_nsec -= N1e9;
        } else if (to.tv_nsec < 0) {
            to.tv_sec -= 1;
            to.tv_nsec += N1e9;
        }

        while (ret) {
            ldebug("increase mode, sleep to %ld.%ld", to.tv_sec, to.tv_nsec);
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &to, 0);
            if (ret && ret != EINTR) {
                lfatal("clock_nanosleep(%ld.%ld) %d", to.tv_sec, to.tv_nsec, ret);
            }
        }
#elif HAVE_NANOSLEEP
        while (ret) {
            ldebug("increase mode, sleep for %ld.%ld", diff.tv_sec, diff.tv_nsec);
            if ((ret = nanosleep(&diff, &diff))) {
                ret = errno;
                if (ret != EINTR) {
                    lfatal("nanosleep(%ld.%ld) %d", diff.tv_sec, diff.tv_nsec, ret);
                }
            }
        }
#endif
    }

    _self->last_pkthdr_ts = pkt->ts;

#if HAVE_CLOCK_NANOSLEEP
    if (clock_gettime(CLOCK_MONOTONIC, &_self->last_ts)) {
        lfatal("clock_gettime()");
    }
#endif

    self->recv(self->ctx, obj);

    return 0;
}

static int _reduce(filter_timing_t* self, const core_object_packet_t* pkt, const core_object_t* obj)
{
    _filter_timing_t* _self = (_filter_timing_t*)self;
    struct timespec   diff  = {
        pkt->ts.sec - _self->last_pkthdr_ts.sec,
        pkt->ts.nsec - _self->last_pkthdr_ts.nsec
    };
    int ret = EINTR;

    if (diff.tv_nsec >= N1e9) {
        diff.tv_sec += 1;
        diff.tv_nsec -= N1e9;
    } else if (diff.tv_nsec < 0) {
        diff.tv_sec -= 1;
        diff.tv_nsec += N1e9;
    }

    diff.tv_sec -= _self->mod_ts.tv_sec;
    diff.tv_nsec -= _self->mod_ts.tv_nsec;
    if (diff.tv_nsec < 0) {
        diff.tv_sec -= 1;
        diff.tv_nsec += N1e9;
    }

    if (diff.tv_sec > -1 && diff.tv_nsec > -1) {
#if HAVE_CLOCK_NANOSLEEP
        struct timespec to = {
            _self->last_ts.tv_sec + diff.tv_sec,
            _self->last_ts.tv_nsec + diff.tv_nsec
        };

        if (to.tv_nsec >= N1e9) {
            to.tv_sec += 1;
            to.tv_nsec -= N1e9;
        } else if (to.tv_nsec < 0) {
            to.tv_sec -= 1;
            to.tv_nsec += N1e9;
        }

        while (ret) {
            ldebug("reduce mode, sleep to %ld.%ld", to.tv_sec, to.tv_nsec);
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &to, 0);
            if (ret && ret != EINTR) {
                lfatal("clock_nanosleep(%ld.%ld) %d", to.tv_sec, to.tv_nsec, ret);
            }
        }
#elif HAVE_NANOSLEEP
        while (ret) {
            ldebug("reduce mode, sleep for %ld.%ld", diff.tv_sec, diff.tv_nsec);
            if ((ret = nanosleep(&diff, &diff))) {
                ret = errno;
                if (ret != EINTR) {
                    lfatal("nanosleep(%ld.%ld) %d", diff.tv_sec, diff.tv_nsec, ret);
                }
            }
        }
#endif
    }

    _self->last_pkthdr_ts = pkt->ts;

#if HAVE_CLOCK_NANOSLEEP
    if (clock_gettime(CLOCK_MONOTONIC, &_self->last_ts)) {
        lfatal("clock_gettime()");
    }
#endif

    self->recv(self->ctx, obj);

    return 0;
}

static int _multiply(filter_timing_t* self, const core_object_packet_t* pkt, const core_object_t* obj)
{
    _filter_timing_t* _self = (_filter_timing_t*)self;
    struct timespec   diff  = {
        pkt->ts.sec - _self->last_pkthdr_ts.sec,
        pkt->ts.nsec - _self->last_pkthdr_ts.nsec
    };
    int ret = EINTR;

    if (diff.tv_nsec >= N1e9) {
        diff.tv_sec += 1;
        diff.tv_nsec -= N1e9;
    } else if (diff.tv_nsec < 0) {
        diff.tv_sec -= 1;
        diff.tv_nsec += N1e9;
    }

    diff.tv_sec  = (time_t)((float)diff.tv_sec * self->mul);
    diff.tv_nsec = (long)((float)diff.tv_nsec * self->mul);
    if (diff.tv_nsec >= N1e9) {
        diff.tv_sec += diff.tv_nsec / N1e9;
        diff.tv_nsec %= N1e9;
    }

    if (diff.tv_sec > -1 && diff.tv_nsec > -1) {
#if HAVE_CLOCK_NANOSLEEP
        struct timespec to = {
            _self->last_ts.tv_sec + diff.tv_sec,
            _self->last_ts.tv_nsec + diff.tv_nsec
        };

        if (to.tv_nsec >= N1e9) {
            to.tv_sec += 1;
            to.tv_nsec -= N1e9;
        } else if (to.tv_nsec < 0) {
            to.tv_sec -= 1;
            to.tv_nsec += N1e9;
        }

        while (ret) {
            ldebug("multiply mode, sleep to %ld.%ld", to.tv_sec, to.tv_nsec);
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &to, 0);
            if (ret && ret != EINTR) {
                lfatal("clock_nanosleep(%ld.%ld) %d", to.tv_sec, to.tv_nsec, ret);
            }
        }
#elif HAVE_NANOSLEEP
        while (ret) {
            ldebug("multiply mode, sleep for %ld.%ld", diff.tv_sec, diff.tv_nsec);
            if ((ret = nanosleep(&diff, &diff))) {
                ret = errno;
                if (ret != EINTR) {
                    lfatal("nanosleep(%ld.%ld) %d", diff.tv_sec, diff.tv_nsec, ret);
                }
            }
        }
#endif
    }

    _self->last_pkthdr_ts = pkt->ts;

#if HAVE_CLOCK_NANOSLEEP
    if (clock_gettime(CLOCK_MONOTONIC, &_self->last_ts)) {
        lfatal("clock_gettime()");
    }
#endif

    self->recv(self->ctx, obj);

    return 0;
}

static int _init(filter_timing_t* self, const core_object_packet_t* pkt, const core_object_t* obj)
{
    _filter_timing_t* _self = (_filter_timing_t*)self;

#if HAVE_CLOCK_NANOSLEEP
    if (clock_gettime(CLOCK_MONOTONIC, &_self->last_ts)) {
        lfatal("clock_gettime()");
    }
    _self->diff = _self->last_ts;
    _self->diff.tv_sec -= pkt->ts.sec;
    _self->diff.tv_nsec -= pkt->ts.nsec;
    ldebug("init with clock_nanosleep() now is %ld.%ld, diff of first pkt %ld.%ld",
        _self->last_ts.tv_sec, _self->last_ts.tv_nsec,
        _self->diff.tv_sec, _self->diff.tv_nsec);
#elif HAVE_NANOSLEEP
    ldebug("init with nanosleep()");
#else
#error "No clock_nanosleep() or nanosleep(), can not continue"
#endif

    _self->last_pkthdr_ts = pkt->ts;

    switch (self->mode) {
    case TIMING_MODE_KEEP:
        ldebug("init mode keep");
        _self->timing_callback = _keep;
        break;
    case TIMING_MODE_INCREASE:
        _self->timing_callback = _increase;
        _self->mod_ts.tv_sec   = self->inc / N1e9;
        _self->mod_ts.tv_nsec  = self->inc % N1e9;
        ldebug("init mode increase by %ld.%ld", _self->mod_ts.tv_sec, _self->mod_ts.tv_nsec);
        break;
    case TIMING_MODE_REDUCE:
        _self->timing_callback = _reduce;
        _self->mod_ts.tv_sec   = self->red / N1e9;
        _self->mod_ts.tv_nsec  = self->red % N1e9;
        ldebug("init mode reduce by %ld.%ld", _self->mod_ts.tv_sec, _self->mod_ts.tv_nsec);
        break;
    case TIMING_MODE_MULTIPLY:
        _self->timing_callback = _multiply;
        ldebug("init mode multiply by %f", self->mul);
        break;
    default:
        lfatal("invalid timing mode %d", self->mode);
        return 1;
    }

    self->recv(self->ctx, obj);

    return 0;
}

filter_timing_t* filter_timing_new()
{
    filter_timing_t*  self  = malloc(sizeof(_filter_timing_t));
    _filter_timing_t* _self = (_filter_timing_t*)self;

    if (self) {
        *self                  = _defaults;
        _self->timing_callback = _init;

        ldebug("new");
    }

    return self;
}

void filter_timing_free(filter_timing_t* self)
{
    ldebug("free");
    free(self);
}

static int _receive(void* ctx, const core_object_t* obj)
{
    _filter_timing_t*           _self = (_filter_timing_t*)ctx;
    const core_object_packet_t* pkt   = (core_object_packet_t*)obj;

    if (!_self || !obj || !_self->pub.recv) {
        return 1;
    }

    while (pkt) {
        if (pkt->obj_type == CORE_OBJECT_PACKET) {
            return _self->timing_callback((filter_timing_t*)_self, pkt, obj);
        }
        pkt = (core_object_packet_t*)pkt->obj_prev;
    }

    return 0;
}

core_receiver_t filter_timing_receiver()
{
    return _receive;
}

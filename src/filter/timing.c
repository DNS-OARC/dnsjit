/*
 * Copyright (c) 2018-2021, OARC, Inc.
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
#include "core/assert.h"
#include "core/timespec.h"
#include "core/object/pcap.h"

#include <time.h>
#include <sys/time.h>

#define N1e9 1000000000

typedef struct _filter_timing {
    filter_timing_t pub;

    struct timespec diff;
    core_timespec_t last_pkthdr_ts;
    struct timespec last_ts;
    struct timespec first_ts;
    void (*timing_callback)(filter_timing_t*, const core_object_pcap_t*);
    struct timespec mod_ts;
    size_t          counter;
} _filter_timing_t;

static core_log_t      _log      = LOG_T_INIT("filter.timing");
static filter_timing_t _defaults = {
    LOG_T_INIT_OBJ("filter.timing"),
    0, 0,
    TIMING_MODE_KEEP, 0, 0, 0, 0, 0.0, 0,
    0, 0
};

#define _self ((_filter_timing_t*)self)

core_log_t* filter_timing_log()
{
    return &_log;
}

static void _keep(filter_timing_t* self, const core_object_pcap_t* pkt)
{
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
        ldebug("keep mode, sleep to %ld.%09ld", to.tv_sec, to.tv_nsec);
        ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &to, 0);
        if (ret && ret != EINTR) {
            lfatal("clock_nanosleep(%ld.%09ld) %d", to.tv_sec, to.tv_nsec, ret);
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
            ldebug("keep mode, sleep for %ld.%09ld", diff.tv_sec, diff.tv_nsec);
            if ((ret = nanosleep(&diff, &diff))) {
                ret = errno;
                if (ret != EINTR) {
                    lfatal("nanosleep(%ld.%09ld) %d", diff.tv_sec, diff.tv_nsec, ret);
                }
            }
        }
    }

    _self->last_pkthdr_ts = pkt->ts;
#endif
}

static void _increase(filter_timing_t* self, const core_object_pcap_t* pkt)
{
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
            ldebug("increase mode, sleep to %ld.%09ld", to.tv_sec, to.tv_nsec);
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &to, 0);
            if (ret && ret != EINTR) {
                lfatal("clock_nanosleep(%ld.%09ld) %d", to.tv_sec, to.tv_nsec, ret);
            }
        }
#elif HAVE_NANOSLEEP
        while (ret) {
            ldebug("increase mode, sleep for %ld.%09ld", diff.tv_sec, diff.tv_nsec);
            if ((ret = nanosleep(&diff, &diff))) {
                ret = errno;
                if (ret != EINTR) {
                    lfatal("nanosleep(%ld.%09ld) %d", diff.tv_sec, diff.tv_nsec, ret);
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
}

static void _reduce(filter_timing_t* self, const core_object_pcap_t* pkt)
{
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
            ldebug("reduce mode, sleep to %ld.%09ld", to.tv_sec, to.tv_nsec);
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &to, 0);
            if (ret && ret != EINTR) {
                lfatal("clock_nanosleep(%ld.%09ld) %d", to.tv_sec, to.tv_nsec, ret);
            }
        }
#elif HAVE_NANOSLEEP
        while (ret) {
            ldebug("reduce mode, sleep for %ld.%09ld", diff.tv_sec, diff.tv_nsec);
            if ((ret = nanosleep(&diff, &diff))) {
                ret = errno;
                if (ret != EINTR) {
                    lfatal("nanosleep(%ld.%09ld) %d", diff.tv_sec, diff.tv_nsec, ret);
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
}

static void _multiply(filter_timing_t* self, const core_object_pcap_t* pkt)
{
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
            ldebug("multiply mode, sleep to %ld.%09ld", to.tv_sec, to.tv_nsec);
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &to, 0);
            if (ret && ret != EINTR) {
                lfatal("clock_nanosleep(%ld.%09ld) %d", to.tv_sec, to.tv_nsec, ret);
            }
        }
#elif HAVE_NANOSLEEP
        while (ret) {
            ldebug("multiply mode, sleep for %ld.%09ld", diff.tv_sec, diff.tv_nsec);
            if ((ret = nanosleep(&diff, &diff))) {
                ret = errno;
                if (ret != EINTR) {
                    lfatal("nanosleep(%ld.%09ld) %d", diff.tv_sec, diff.tv_nsec, ret);
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
}

static void _fixed(filter_timing_t* self, const core_object_pcap_t* pkt)
{
    struct timespec diff = {
        _self->mod_ts.tv_sec,
        _self->mod_ts.tv_nsec
    };
    int ret = EINTR;

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
            ldebug("fixed mode, sleep to %ld.%09ld", to.tv_sec, to.tv_nsec);
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &to, 0);
            if (ret && ret != EINTR) {
                lfatal("clock_nanosleep(%ld.%09ld) %d", to.tv_sec, to.tv_nsec, ret);
            }
        }
#elif HAVE_NANOSLEEP
        while (ret) {
            ldebug("fixed mode, sleep for %ld.%09ld", diff.tv_sec, diff.tv_nsec);
            if ((ret = nanosleep(&diff, &diff))) {
                ret = errno;
                if (ret != EINTR) {
                    lfatal("nanosleep(%ld.%09ld) %d", diff.tv_sec, diff.tv_nsec, ret);
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
}

#if HAVE_CLOCK_NANOSLEEP
static inline void _timespec_diff(struct timespec* start, struct timespec* stop,
    struct timespec* result)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        mlassert(stop->tv_sec > start->tv_sec, "stop time must be after start time");
        result->tv_sec  = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000UL;
    } else {
        mlassert(stop->tv_sec >= start->tv_sec, "stop time must be after start time");
        result->tv_sec  = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }
}

static void _realtime(filter_timing_t* self, const core_object_pcap_t* pkt)
{
    _self->counter++;
    if (_self->counter >= self->rt_batch) {
        struct timespec simulated;

        _self->counter = 0;
        if (clock_gettime(CLOCK_MONOTONIC, &_self->last_ts)) {
            lfatal("clock_gettime()");
        }

        // calculate simulated time from packet offsets
        simulated.tv_sec  = pkt->ts.sec;
        simulated.tv_nsec = pkt->ts.nsec;
        _timespec_diff(&_self->mod_ts, &simulated, &simulated);

        // calculate real elapsed time from monotonic clock
        _timespec_diff(&_self->first_ts, &_self->last_ts, &_self->diff);

        linfo("simulated time: %ld.%09lds; real time: %ld.%09lds",
            simulated.tv_sec, simulated.tv_nsec, _self->diff.tv_sec, _self->diff.tv_nsec);

        if (simulated.tv_sec > _self->diff.tv_sec
            || (simulated.tv_sec == _self->diff.tv_sec && simulated.tv_nsec > _self->diff.tv_nsec)) {
            int ret = EINTR;
            _timespec_diff(&_self->diff, &simulated, &simulated);

            ldebug("sleeping for %ld.%09lds", simulated.tv_sec, simulated.tv_nsec);
            while (ret) {
                ret = clock_nanosleep(CLOCK_MONOTONIC, 0, &simulated, 0);
                if (ret && ret != EINTR) {
                    lfatal("clock_nanosleep(%ld.%09ld) %d", simulated.tv_sec, simulated.tv_nsec, ret);
                }
            }
        } else {
            // check that real time didn't drift ahead more than specified drift limit
            _timespec_diff(&simulated, &_self->diff, &_self->diff);
            if (_self->diff.tv_sec > (self->rt_drift / N1e9)
                || (_self->diff.tv_sec == (self->rt_drift / N1e9) && _self->diff.tv_nsec >= (self->rt_drift % N1e9))) {
                lfatal("aborting, real time drifted ahead of simulated time (%ld.%09lds) by %ld.%09lds",
                    simulated.tv_sec, simulated.tv_nsec, _self->diff.tv_sec, _self->diff.tv_nsec);
            }
        }
    }
}
#endif

static void _init(filter_timing_t* self, const core_object_pcap_t* pkt)
{
#if HAVE_CLOCK_NANOSLEEP
    if (clock_gettime(CLOCK_MONOTONIC, &_self->last_ts)) {
        lfatal("clock_gettime()");
    }
    _self->first_ts = _self->last_ts;
    _self->diff     = _self->last_ts;
    _self->diff.tv_sec -= pkt->ts.sec;
    _self->diff.tv_nsec -= pkt->ts.nsec;
    ldebug("init with clock_nanosleep() now is %ld.%09ld, diff of first pkt %ld.%09ld",
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
        ldebug("init mode increase by %ld.%09ld", _self->mod_ts.tv_sec, _self->mod_ts.tv_nsec);
        break;
    case TIMING_MODE_REDUCE:
        _self->timing_callback = _reduce;
        _self->mod_ts.tv_sec   = self->red / N1e9;
        _self->mod_ts.tv_nsec  = self->red % N1e9;
        ldebug("init mode reduce by %ld.%09ld", _self->mod_ts.tv_sec, _self->mod_ts.tv_nsec);
        break;
    case TIMING_MODE_MULTIPLY:
        _self->timing_callback = _multiply;
        ldebug("init mode multiply by %f", self->mul);
        break;
    case TIMING_MODE_FIXED:
        _self->timing_callback = _fixed;
        _self->mod_ts.tv_sec   = self->fixed / N1e9;
        _self->mod_ts.tv_nsec  = self->fixed % N1e9;
        ldebug("init mode fixed by %ld.%09ld", _self->mod_ts.tv_sec, _self->mod_ts.tv_nsec);
        break;
    case TIMING_MODE_REALTIME:
#if HAVE_CLOCK_NANOSLEEP
        ldebug("init mode realtime");
        _self->timing_callback = _realtime;
        _self->counter         = 0;
        _self->mod_ts.tv_sec   = pkt->ts.sec;
        _self->mod_ts.tv_nsec  = pkt->ts.nsec;
#else
        lfatal("realtime mode requires clock_nanosleep()");
#endif
        break;
    default:
        lfatal("invalid timing mode %d", self->mode);
    }
}

filter_timing_t* filter_timing_new()
{
    filter_timing_t* self;
    mlfatal_oom(self = malloc(sizeof(_filter_timing_t)));
    *self                  = _defaults;
    _self->timing_callback = _init;

    return self;
}

void filter_timing_free(filter_timing_t* self)
{
    mlassert_self();
    free(self);
}

static void _receive(filter_timing_t* self, const core_object_t* obj)
{
    mlassert_self();
    lassert(obj, "obj is nil");

    if (obj->obj_type != CORE_OBJECT_PCAP) {
        lfatal("obj is not CORE_OBJECT_PCAP");
    }

    _self->timing_callback(self, (core_object_pcap_t*)obj);
    self->recv(self->ctx, obj);
}

core_receiver_t filter_timing_receiver(filter_timing_t* self)
{
    mlassert_self();

    if (!self->recv) {
        lfatal("no receiver set");
    }

    return (core_receiver_t)_receive;
}

static const core_object_t* _produce(filter_timing_t* self)
{
    const core_object_t* obj;
    mlassert_self();

    obj = self->prod(self->prod_ctx);
    if (!obj || obj->obj_type != CORE_OBJECT_PCAP) {
        return 0;
    }

    _self->timing_callback(self, (core_object_pcap_t*)obj);
    return obj;
}

core_producer_t filter_timing_producer(filter_timing_t* self)
{
    mlassert_self();

    if (!self->prod) {
        lfatal("no producer set");
    }

    return (core_producer_t)_produce;
}

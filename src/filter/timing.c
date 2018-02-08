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

#include <time.h>
#include <sys/time.h>

static log_t           _log      = LOG_T_INIT("filter.timing");
static filter_timing_t _defaults = {
    LOG_T_INIT_OBJ("filter.timing"), 0, 0,
    TIMING_MODE_KEEP, 0, 0, 0.0,
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }
};

log_t* filter_timing_log()
{
    return &_log;
}

int filter_timing_init(filter_timing_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("init %p", self);

    *self = _defaults;

    return 0;
}

int filter_timing_destroy(filter_timing_t* self)
{
    if (!self) {
        return 1;
    }

    ldebug("destroy %p", self);

    return 0;
}

static int _receive(void* robj, query_t* q)
{
    filter_timing_t* self = (filter_timing_t*)robj;
    struct timespec  now  = { 0, 0 };
    struct timeval   last_packet, ts;
    struct timespec  last_time;
    struct timespec  last_realtime;
    struct timespec  last_time_queue;

    if (!self || !q || !self->recv) {
        query_free(q);
        return 1;
    }

    ts.tv_sec  = q->ts.sec;
    ts.tv_usec = q->ts.nsec / 1000;

    last_packet.tv_sec  = self->last_packet.sec;
    last_packet.tv_usec = self->last_packet.nsec / 1000;

    ldebug("pkthdr.ts %lu.%06lu", ts.tv_sec, ts.tv_usec);
    ldebug("last_packet %lu.%06lu", last_packet.tv_sec, last_packet.tv_usec);

    if (clock_gettime(CLOCK_MONOTONIC, &now)) {
        lfatal("clock_gettime()");
    }

    if ((self->last_time_queue.sec || self->last_time_queue.nsec)
        && last_packet.tv_sec
        && (self->last_time.sec || self->last_time.nsec)
        && timercmp(&ts, &last_packet, >)) {
        struct timespec pdiff = { 0, 0 };
        struct timeval  diff;
        struct timespec sleep_to;

        if (now.tv_sec > self->last_time_queue.sec)
            pdiff.tv_sec = now.tv_sec - self->last_time_queue.sec;
        if (now.tv_nsec > self->last_time_queue.nsec)
            pdiff.tv_nsec = now.tv_nsec - self->last_time_queue.nsec;

        if (self->last_time_queue.sec > self->last_time.sec)
            pdiff.tv_sec += self->last_time_queue.sec - self->last_time.sec;
        if (self->last_time_queue.nsec > self->last_time.nsec)
            pdiff.tv_nsec += self->last_time_queue.nsec - self->last_time.nsec;

        if (pdiff.tv_nsec > 999999999) {
            pdiff.tv_sec += pdiff.tv_nsec / 1000000000;
            pdiff.tv_nsec %= 1000000000;
        }

        ldebug("process diff %lu.%09lu", pdiff.tv_sec, pdiff.tv_nsec);

        timersub(&ts, &last_packet, &diff);

        ldebug("diff %lu.%06lu", diff.tv_sec, diff.tv_usec);

        if (self->mode == TIMING_MODE_MULTIPLY) {
            diff.tv_sec  = (long)((float)diff.tv_sec * self->mul);
            diff.tv_usec = (long)((float)diff.tv_usec * self->mul);
            if (diff.tv_sec < 0 || diff.tv_usec < 0) {
                diff.tv_sec  = 0;
                diff.tv_usec = 0;
            }
        }

#if HAVE_CLOCK_NANOSLEEP
        /* absolute time */
        sleep_to.tv_sec  = self->last_time.sec;
        sleep_to.tv_nsec = self->last_time.nsec;
#elif HAVE_NANOSLEEP
        /* relative time */
        sleep_to.tv_sec  = 0;
        sleep_to.tv_nsec = 0;
#else
#error "No clock_nanosleep() or nanosleep(), can not continue"
#endif

        sleep_to.tv_nsec += diff.tv_usec * 1000;
        if (sleep_to.tv_nsec > 999999999) {
            sleep_to.tv_sec += sleep_to.tv_nsec / 1000000000;
            sleep_to.tv_nsec %= 1000000000;
        }
        sleep_to.tv_sec += diff.tv_sec;

        if (pdiff.tv_sec) {
            if (sleep_to.tv_sec > pdiff.tv_sec)
                sleep_to.tv_sec -= pdiff.tv_sec;
            else
                sleep_to.tv_sec = 0;
        }
        if (pdiff.tv_nsec) {
            if (sleep_to.tv_nsec >= pdiff.tv_nsec)
                sleep_to.tv_nsec -= pdiff.tv_nsec;
            else if (sleep_to.tv_sec) {
                sleep_to.tv_sec -= 1;
                sleep_to.tv_nsec += 1000000000 - pdiff.tv_nsec;
            } else
                sleep_to.tv_nsec = 0;
        }

        switch (self->mode) {
        case TIMING_MODE_INCREASE:
            sleep_to.tv_nsec += self->inc;
            break;

        case TIMING_MODE_REDUCE: {
            unsigned long int nsec = self->red;

            if (nsec > 999999999) {
                unsigned long int sec = nsec / 1000000000;
                if (sleep_to.tv_sec > sec)
                    sleep_to.tv_sec -= sec;
                else
                    sleep_to.tv_sec = 0;
                nsec %= 1000000000;
            }
            if (nsec) {
                if (sleep_to.tv_nsec >= nsec)
                    sleep_to.tv_nsec -= nsec;
                else if (sleep_to.tv_sec) {
                    sleep_to.tv_sec -= 1;
                    sleep_to.tv_nsec += 1000000000 - nsec;
                } else
                    sleep_to.tv_nsec = 0;
            }
        } break;

        default:
            break;
        }

        if (sleep_to.tv_nsec > 999999999) {
            sleep_to.tv_sec += sleep_to.tv_nsec / 1000000000;
            sleep_to.tv_nsec %= 1000000000;
        }

        ldebug("last %lu.%09lu", self->last_time.sec, self->last_time.nsec);
        ldebug("now %lu.%09lu", now.tv_sec, now.tv_nsec);
        ldebug("sleep_to %lu.%09lu", sleep_to.tv_sec, sleep_to.tv_nsec);

#if HAVE_CLOCK_NANOSLEEP
        if (self->mode != TIMING_MODE_BEST_EFFORT
            && (sleep_to.tv_sec < now.tv_sec
                   || (sleep_to.tv_sec == now.tv_sec && sleep_to.tv_nsec < now.tv_nsec))) {
            ldebug("Unable to keep up with timings (process cost %lu.%09lu, packet diff %lu.%06lu, now %lu.%09lu, sleep to %lu.%09lu)",
                pdiff.tv_sec, pdiff.tv_nsec,
                diff.tv_sec, diff.tv_usec,
                now.tv_sec, now.tv_nsec,
                sleep_to.tv_sec, sleep_to.tv_nsec);
            sleep_to.tv_sec  = 0;
            sleep_to.tv_nsec = 0;
        }

        if (sleep_to.tv_sec || sleep_to.tv_nsec) {
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &sleep_to, 0);
        }
#elif HAVE_NANOSLEEP
#define SAVE_REALTIME 1
        /* sleep_to will be relative, need to check against now - last_time */
        if (self->mode != TIMING_MODE_BEST_EFFORT
            && (sleep_to.tv_sec < (now.tv_sec - self->last_time.sec)
                   || (sleep_to.tv_sec == (now.tv_sec - self->last_time.sec) && sleep_to.tv_nsec < (now.tv_nsec - self->last_time.nsec)))) {
            ldebug("Unable to keep up with timings (process cost %lu.%09lu, packet diff %lu.%06lu, now %lu.%09lu, sleep to %lu.%09lu)",
                pdiff.tv_sec, pdiff.tv_nsec,
                diff.tv_sec, diff.tv_usec,
                now.tv_sec, now.tv_nsec,
                self->last_time.sec + sleep_to.tv_sec, self->last_time.nsec + sleep_to.tv_nsec);
            sleep_to.tv_sec  = 0;
            sleep_to.tv_nsec = 0;
        }

        if (sleep_to.tv_sec || sleep_to.tv_nsec) {
            nanosleep(&sleep_to, 0);
        }
#endif
    }

    if (clock_gettime(CLOCK_MONOTONIC, &last_time)) {
        lfatal("clock_gettime()");
        // self->last_time.tv_sec  = 0;
        // self->last_time.tv_nsec = 0;
    }
    self->last_time.sec  = last_time.tv_sec;
    self->last_time.nsec = last_time.tv_nsec;
#ifdef SAVE_REALTIME
    if (clock_gettime(CLOCK_REALTIME, &last_realtime)) {
        lfatal("clock_gettime()");
        // self->last_realtime.tv_sec  = 0;
        // self->last_realtime.tv_nsec = 0;
        // self->last_time.tv_sec      = 0;
        // self->last_time.tv_nsec     = 0;
    }
#endif
    self->last_realtime.sec  = last_realtime.tv_sec;
    self->last_realtime.nsec = last_realtime.tv_nsec;

    self->last_packet = q->ts;

    self->recv(self->robj, q);

    if (clock_gettime(CLOCK_MONOTONIC, &last_time_queue)) {
        lfatal("clock_gettime()");
        // self->last_time_queue.tv_sec  = 0;
        // self->last_time_queue.tv_nsec = 0;
    }
    self->last_time_queue.sec  = last_time_queue.tv_sec;
    self->last_time_queue.nsec = last_time_queue.tv_nsec;

    return 0;
}

receiver_t filter_timing_receiver()
{
    return _receive;
}

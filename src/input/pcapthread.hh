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

#if 0
typedef struct {} pcap_thread_t;
int pcap_thread_snapshot(const pcap_thread_t* pcap_thread);
int pcap_thread_snaplen(const pcap_thread_t* pcap_thread);
int pcap_thread_set_snaplen(pcap_thread_t* pcap_thread, const int snaplen);
int pcap_thread_promiscuous(const pcap_thread_t* pcap_thread);
int pcap_thread_set_promiscuous(pcap_thread_t* pcap_thread, const int promiscuous);
int pcap_thread_monitor(const pcap_thread_t* pcap_thread);
int pcap_thread_set_monitor(pcap_thread_t* pcap_thread, const int monitor);
int pcap_thread_timeout(const pcap_thread_t* pcap_thread);
int pcap_thread_set_timeout(pcap_thread_t* pcap_thread, const int timeout);
int pcap_thread_buffer_size(const pcap_thread_t* pcap_thread);
int pcap_thread_set_buffer_size(pcap_thread_t* pcap_thread, const int buffer_size);
int pcap_thread_immediate_mode(const pcap_thread_t* pcap_thread);
int pcap_thread_set_immediate_mode(pcap_thread_t* pcap_thread, const int immediate_mode);
const char* pcap_thread_filter(const pcap_thread_t* pcap_thread);
int pcap_thread_set_filter(pcap_thread_t* pcap_thread, const char* filter, const size_t filter_len);
int pcap_thread_clear_filter(pcap_thread_t* pcap_thread);
int pcap_thread_filter_errno(const pcap_thread_t* pcap_thread);
int pcap_thread_filter_optimize(const pcap_thread_t* pcap_thread);
int pcap_thread_set_filter_optimize(pcap_thread_t* pcap_thread, const int filter_optimize);
uint32_t pcap_thread_filter_netmask(const pcap_thread_t* pcap_thread);
int pcap_thread_set_filter_netmask(pcap_thread_t* pcap_thread, const uint32_t filter_netmask);
#endif

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")
//lua:require("dnsjit.core.timespec_h")

typedef struct input_pcapthread {
    core_log_t      _log;
    unsigned short  setup_ok : 1;
    unsigned short  only_queries : 1;
    pcap_thread_t*  pt;
    core_receiver_t recv;
    void*           ctx;
    core_timespec_t ts, te;
    size_t          pkts, drop, ignore, queries;
    int             err;
    uint64_t        src_id;
    uint64_t        qr_id;
} input_pcapthread_t;

core_log_t* input_pcapthread_log();

int input_pcapthread_init(input_pcapthread_t* self);
int input_pcapthread_destroy(input_pcapthread_t* self);
int input_pcapthread_open(input_pcapthread_t* self, const char* device);
int input_pcapthread_open_offline(input_pcapthread_t* self, const char* file);
int input_pcapthread_run(input_pcapthread_t* self);
int input_pcapthread_next(input_pcapthread_t* self);
const char* input_pcapthread_errbuf(input_pcapthread_t* self);
const char* input_pcapthread_strerr(int err);

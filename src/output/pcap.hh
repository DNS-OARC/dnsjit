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

#if 0
typedef struct pcap_dumper {} pcap_dumper_t;
#endif

//lua:require("dnsjit.core.log")
//lua:require("dnsjit.core.receiver_h")
//lua:require("dnsjit.input.pcap_h")

typedef struct output_pcap {
    core_log_t     _log;
    pcap_t*        pcap;
    pcap_dumper_t* dumper;
} output_pcap_t;

core_log_t* output_pcap_log();
void        output_pcap_init(output_pcap_t* self);
void        output_pcap_destroy(output_pcap_t* self);
int         output_pcap_open(output_pcap_t* self, const char* file, int linktype, int snaplen);
void        output_pcap_close(output_pcap_t* self);
int         output_pcap_have_errors(output_pcap_t* self);

core_receiver_t output_pcap_receiver(output_pcap_t* self);

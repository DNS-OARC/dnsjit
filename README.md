# Engine for capturing, parsing and replaying DNS

[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=dns-oarc%3Adnsjit&metric=bugs)](https://sonarcloud.io/summary/new_code?id=dns-oarc%3Adnsjit) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=dns-oarc%3Adnsjit&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=dns-oarc%3Adnsjit)

**dnsjit** is a combination of parts taken from **dsc**, **dnscap**, **drool**,
and put together around Lua to create a script-based engine for easy
capturing, parsing and statistics gathering of DNS messages while also
providing facilities for replaying DNS traffic.

One of the core functionality that **dnsjit** brings is to tie together C
and Lua modules through a receiver/producer interface.
This allows creation of custom chains of functionality to meet various
requirements.
Another core functionality is the ability to parse and process DNS messages
even if the messages are non-compliant with the DNS standards.

The following Lua module categories exists:
- `dnsjit.core`: Core modules for handling things like logging, DNS messages and receiver/receive functionality.
- `dnsjit.lib`: Various Lua libraries or C library bindings.
- `dnsjit.input`: Input modules used to read DNS messages in various ways.
- `dnsjit.filter`: Filter modules to process or manipulate DNS messages.
- `dnsjit.output`: Output modules used to display DNS message, export to various formats or replay them against other targets.

See each category's man-page for more information.

More information may be found here:
- https://www.dns-oarc.net/tools/dnsjit

Issues should be reported here:
- https://github.com/DNS-OARC/dnsjit/issues

General support and discussion:
- Mattermost: https://chat.dns-oarc.net/community/channels/oarc-software

## Packages

https://dev.dns-oarc.net/packages

Packages for Debian, Ubuntu, EPEL, SLE, openSUSE can be found in the
PRE-RELEASE channel. Some distributions are limited to certain
architectures because of LuaJIT.

## Dependencies

- [libluajit](http://luajit.org/) 2.0+ (or compatible alternatives)
- [libpcap](http://www.tcpdump.org/)
- [liblmdb](https://github.com/LMDB/lmdb)
- [libck](https://github.com/concurrencykit/ck)
- [libgnutls](https://www.gnutls.org/)
- [liblz4](http://www.lz4.org/)
- [libzstd](http://www.zstd.net/)
- [luajit](http://luajit.org/) (for building)
- automake/autoconf/libtool/pkg-config (for building)

Debian/Ubuntu: `apt-get install libluajit-5.1-dev libpcap-dev luajit liblmdb-dev libck-dev libgnutls28-dev liblz4-dev libzstd-dev`
- Note: On Xenial you'll need to install `libzstd1-dev`

CentOS: `yum install luajit-devel libpcap-devel lmdb-devel ck-devel gnutls-devel lz4-devel libzstd-devel`
- Note: You might need EPEL and/or PowerTools repositories enabled

FreeBSD: `pkg install luajit libpcap lmdb gnutls concurrencykit zstd liblz4`

OpenBSD: `pkg_add luajit gnutls lz4 zstd` + manual install of libpcap, liblmdb and libck

On some version of SUSE Linux Enterprise moonjit is used as an compatible
alternative to luajit.

## Build

```shell
git clone https://github.com/DNS-OARC/dnsjit
cd dnsjit
sh autogen.sh
./configure
make
```

## Documentation

Most documentation exists in man-pages and you do not have to install to
access them, after building you can do:

```shell
man src/dnsjit.1
man src/dnsjit.core.3
man src/dnsjit.lib.3
man src/dnsjit.input.3
man src/dnsjit.filter.3
man src/dnsjit.output.3
```

## Usage

Run a Lua script:

```shell
dnsjit file.lua ...
```

Shebang-style:
```lua
#!/usr/bin/env dnsjit
...
```

## Example

Following example display the DNS ID found in queries.

```lua
require("dnsjit.core.objects")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local dns = require("dnsjit.core.object.dns").new()

input:open_offline(arg[2])
layer:producer(input)
local producer, ctx = layer:produce()

while true do
    local object = producer(ctx)
    if object == nil then break end
    if object:type() == "payload" then
        dns:reset()
        dns.obj_prev = object
        if dns:parse_header() == 0 then
            print(dns.id)
        end
    end
end
```

Disclaimer, to keep the above example short it only works on pre-prepared
PCAPs with only UDP DNS traffic in them.

See more examples in the [examples](https://github.com/DNS-OARC/dnsjit/tree/develop/examples) directory.

## Copyright

Copyright (c) 2018-2025 OARC, Inc.

All rights reserved.

```
This file is part of dnsjit.

dnsjit is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

dnsjit is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with dnsjit.  If not, see <http://www.gnu.org/licenses/>.
```

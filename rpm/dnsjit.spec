Name:           dnsjit
Version:        1.1.0
Release:        1%{?dist}
Summary:        Engine for capturing, parsing and replaying DNS
Group:          Productivity/Networking/DNS/Utilities

License:        GPL-3.0-or-later
URL:            https://github.com/DNS-OARC/dnsjit
# Source needs to be generated by dist-tools/create-source-packages, see
# https://github.com/jelu/dist-tools
Source0:        https://github.com/DNS-OARC/dnsjit/archive/v%{version}.tar.gz?/%{name}_%{version}.orig.tar.gz

BuildRequires:  libpcap-devel
%if 0%{?suse_version} || 0%{?sle_version}
BuildRequires:  moonjit-devel >= 2.0.0
%else
BuildRequires:  luajit-devel >= 2.0.0
%endif
BuildRequires:  lmdb-devel
BuildRequires:  ck-devel
BuildRequires:  gnutls-devel
BuildRequires:  lz4-devel >= 1.8.0
BuildRequires:  libzstd-devel >= 1.3.0
BuildRequires:  autoconf >= 2.64
BuildRequires:  automake
BuildRequires:  libtool

%description
dnsjit is a combination of parts taken from dsc, dnscap, drool,
and put together around Lua to create a script-based engine for easy
capturing, parsing and statistics gathering of DNS message while also
providing facilities for replaying DNS traffic.


%package devel
Summary:    Engine for capturing, parsing and replaying DNS - development files
Group:      Development/Libraries/C and C++
Requires:   libpcap-devel
%if 0%{?suse_version} || 0%{?sle_version}
Requires:   moonjit-devel >= 2.0.0
%else
Requires:   luajit-devel >= 2.0.0
%endif
Requires:   ck-devel
Requires:   gnutls-devel

%description devel
dnsjit is a combination of parts taken from dsc, dnscap, drool,
and put together around Lua to create a script-based engine for easy
capturing, parsing and statistics gathering of DNS message while also
providing facilities for replaying DNS traffic.

This package includes development files needed to create dnsjit modules.


%prep
%setup -q -n %{name}_%{version}


%build
sh autogen.sh
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%check
make test


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_datadir}/doc/*
%{_mandir}/man1/*
%{_mandir}/man3/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/*


%changelog
* Wed Feb 03 2021 Jerry Lundström <lundstrom.jerry@gmail.com> 1.1.0-1
- Release 1.1.0
  * This releases adds a new module for handling Base64 URLs and new calls
    for error handling and opening PCAPs using file descriptors, along with
    a bug fix in `lib.getopt` and other changes.
  * The `dnssim` module has also gotten its own version and changelog, this
    is to prepare it for being moved outside of dnsjit's repository in the
    future.
  * New modules, calls, features:
    - New `lib.base64url`: Utility library to convert data to base64url format
    - `core.log`: New call `Log.errstr()`: Convert error number to its text representation
    - `input.fpcap`: New call `Fpcap.openfp()`: Open a PCAP file for processing using a file descriptor, for example `io.stdin`
    - `output.dnssim`: Support for DNS-over-HTTPS
  * Bug fixes:
    - `lib.getopt`: Fix bug where `-` and `--` could not be used as arguments to options
  * Other changes:
    - Fix typo in configure help text
    - Add coverage
    - `filter.ipsplit`: Extend PRNG modulus to 2^31, new implementation is the same as glibc's `rand()`
    - `lib.ip`: Fix typo in documentation
    - `output.dnssim`:
      - This module now has it's own changelog
      - Updated to v20210129
      - Depend on libhttp2 for dnssim DNS-over-HTTPS capabilities
    - `output.pcap`: Log libpcap error when failing to open
    - SUSE packages now depend on moonjit because of lack of LuaJIT support
  * Commits:
    d001ccb m4
    4b63bce output/dnssim: add changelog
    7355810 output/dnssim: add version checks
    95fa6a9 input pcap/fpcap, getopt
    99c3d9f test/test_ipsplit: update to use new PRNG
    3235b09 filter/ipsplit: extend PRNG modulus to 2^31
    8ff81a0 fixup! input.fpcap: filename "-" reads from stdin
    63cf0a4 output/dnssim: fix regression in DoH GET
    367d0b8 input.pcap: document stdin feature of open_offline()
    8d94504 input.fpcap: filename "-" reads from stdin
    617058e getopt: accept singleton - also as option value
    7d7f17c output/dnssim: unify failed to bind error messages
    bdf1517 output/dnssim: add IPv4 support
    15a21da Sonarcloud
    ceeea1d SUSE
    1fc3c82 PR179
    2f5d38f output/dnssim: allow user-set instance log name
    b036c68 Info
    0af1ffb Travis, configure
    49bdc08 output/dnssim: implement udp(tcp_fallback) method
    b4f9cf9 man: update gitlab.labs.nic.cz to gitlab.nic.cz
    45b977d output/dnssim: update man page
    4184090 output/dnssim: https2 - fix connection closure issues
    342f33e output/dnssim: https2 - omit closing connection inside callback
    67a76d5 output/dnssim: handle all states when closing connection
    41f04d8 output/dnssim: document importance of conn state enum ordering
    795ab6f output/dnssim: tls - fix handling of CONGESTED connections
    8792b32 output/dnssim: match QUESTION section of received responses
    3a88f5b Coverage
    4f611c8 dnssim
    6e35d5b Compile
    63faa44 README, format code, man-page
    925f85e lib: add missing man reference
    9239087 output/dnssim: fix man formatting
    bd7bee5 fix lua log levels
    4083efd output/dnssim: fix doc typo
    24c22b8 lib/base64url: add lua bindings
    69be2a1 core/log: add errstr() utility function
    0c14d74 output/dnssim: improve https2() documentation and behaviour
    f74e19c output/pcap: log errors when opening output PCAP
    6fe699a output/dnssim: cleanup and nitpicks
    96db8a9 output/https2: handle max_concurrent_streams similar to nghttp2
    15ea609 output/dnssim: https2 - ensure uri authority is always set
    fad3ed6 output/dnssim: https2 - fix some TODOs
    0bee6d8 output/dnssim: https2 - lua documentation
    e83e010 output/dnssim: https2 - implement GET method
    b553e0f output/dnssim: https2 - configure method
    a431a0d contrib: add base64url functions
    c753097 output/dnssim: https2 - set default concurrent stream limit
    d49f275 output/dnssim: https2 - track number of open streams
    2f7217f output/dnssim: https2 - improve data send edge cases
    c0abebc output/dnssim: https2 - return correct error code on send failure
    5b1f6c3 output/dnssim: conn - avoid assert when tearing down failed connections
    5c42266 output/dnssim: exit when file descriptors run out
    1ab2ab6 output/dnssim: https2 - additional asserts to detect invalid data
    4424eb3 output/dnssim: https2 - check response code
    303f2cd output/dnssim: https2 - improve QID mismatch debug msg
    86e3761 output/dnssim: https2 - bugfixes
    4a52f47 output/dnssim: https2 - use more consistent code style for pointers
    c8d853e output/dnssim: conn - fix potential memory leak
    3e6038b output/dnssim: https2 - enable zero-ing out msgid
    712634c output/dnssim: https2 - properly match dnsmsg to query from http request
    5abe943 output/dnssim: https2 - free memory on teardown
    39a9e9e output/dnssim: https2 - initial implementation
    058aee2 output/dnssim: https2 - initialize and setup session
    85eb4a3 output/dnssim: https2 - add libnghttp2 dependency
    6712bd6 output/dnssim: https2 - add skeleton
* Thu Jul 23 2020 Jerry Lundström <lundstrom.jerry@gmail.com> 1.0.0-1
- Release 1.0.0
* Tue Jun 04 2019 Jerry Lundström <lundstrom.jerry@gmail.com> 0.9.8-1
- Alpha release 0.9.8
* Fri Jan 25 2019 Jerry Lundström <lundstrom.jerry@gmail.com> 0.9.7-1
- Alpha release 0.9.7
* Wed Aug 01 2018 Jerry Lundström <lundstrom.jerry@gmail.com> 0.9.6-1
- Alpha release 0.9.6

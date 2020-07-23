Name:           dnsjit
Version:        1.0.0
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
%if 0%{?suse_version} > 1500
BuildRequires:  luajit-devel >= 2.0.0
%elif 0%{?sle_version} >= 120000 && !0%{?is_opensuse}
BuildRequires:  moonjit-devel >= 2.0.0
%else
BuildRequires:  lua51-luajit >= 2.1.0~beta2
%if 0%{?sle_version} >= 150000 && 0%{?is_opensuse}
BuildRequires:  lua51-luajit-devel >= 2.0.0
%endif
%endif
%else
BuildRequires:  luajit-devel >= 2.0.0
%endif
BuildRequires:  lmdb-devel
BuildRequires:  ck-devel
BuildRequires:  gnutls-devel
BuildRequires:  libuv-devel
BuildRequires:  autoconf >= 2.64
BuildRequires:  automake
BuildRequires:  libtool

%description
dnsjit is a combination of parts taken from dsc, dnscap, drool,
and put together around Lua to create a script-based engine for easy
capturing, parsing and statistics gathering of DNS message while also
providing facilities for replaying DNS traffic.


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
%defattr(-,root,root)
%{_bindir}/*
%{_datadir}/doc/*
%{_mandir}/man1/*
%{_mandir}/man3/*


%changelog
* Thu Jul 23 2020 Jerry Lundström <lundstrom.jerry@gmail.com> 1.0.0-1
- Release 1.0.0
* Tue Jun 04 2019 Jerry Lundström <lundstrom.jerry@gmail.com> 0.9.8-1
- Alpha release 0.9.8
* Fri Jan 25 2019 Jerry Lundström <lundstrom.jerry@gmail.com> 0.9.7-1
- Alpha release 0.9.7
* Wed Aug 01 2018 Jerry Lundström <lundstrom.jerry@gmail.com> 0.9.6-1
- Alpha release 0.9.6

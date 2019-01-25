Name:           dnsjit
Version:        0.9.7
Release:        1%{?dist}
Summary:        Engine for capturing, parsing and replaying DNS
Group:          Productivity/Networking/DNS/Utilities

License:        GPLv3
URL:            https://github.com/DNS-OARC/dnsjit
Source0:        %{name}_%{version}.orig.tar.gz

BuildRequires:  libpcap-devel
BuildRequires:  luajit-devel >= 2.0.0
BuildRequires:  lmdb-devel
BuildRequires:  ck-devel
BuildRequires:  gnutls-devel
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
* Fri Jan 25 2019 Jerry Lundström <lundstrom.jerry@gmail.com> 0.9.7-1
- Alpha release 0.9.7
* Wed Aug 01 2018 Jerry Lundström <lundstrom.jerry@gmail.com> 0.9.6-1
- Alpha release 0.9.6

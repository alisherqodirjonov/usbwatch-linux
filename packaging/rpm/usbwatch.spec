# RPM spec for RHEL / Rocky / Alma 8+, Fedora, openSUSE Leap 15+.
# Built by 'make rpm' (needs rpmbuild); the tarball from 'make dist' is the Source0.
%global debug_package %{nil}
%global _python_bytecompile_errors_terminate_build 0

Name:           usbwatch
Version:        @VERSION@
Release:        1%{?dist}
Summary:        USB device and file activity auditor with a local web console
License:        Proprietary
BuildArch:      noarch
Source0:        usbwatch-linux-%{version}.tar.gz
Requires:       python3 >= 3.6
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
Logs every USB device plugged in (serial, VID:PID, vendor, product, class), every USB
filesystem mounted, and all file activity on USB drives - files written to and read from the
drive, deleted, renamed and executed - with the user and process responsible. Optional
whitelist/blacklist blocking, recovery vault and SHA-256 hashing. Pure Python, no extra
dependencies; the web console listens on localhost only by default and requires sign-in.

%prep
%setup -q -n usbwatch-linux-%{version}

%build
# nothing to build: pure Python

%install
UNITDIR=%{_unitdir} sh scripts/stage.sh %{buildroot} /usr /usr/bin/python3
# SysV scripts are only for non-systemd systems; RPM targets here all use systemd
rm -f %{buildroot}/etc/init.d/usbwatch %{buildroot}/etc/init.d/usbwatch-web %{buildroot}/etc/init.d/usbwatch-common

%pre
getent group usbwatch >/dev/null || groupadd --system usbwatch
getent passwd usbwatch >/dev/null || useradd --system --gid usbwatch --no-create-home \
    --home-dir /var/lib/usbwatch --shell /sbin/nologin --comment "USBWatch web console" usbwatch
exit 0

%post
/usr/lib/usbwatch/pkg-postinst.sh

%preun
if [ $1 -eq 0 ]; then /usr/lib/usbwatch/pkg-prerm.sh remove; else /usr/lib/usbwatch/pkg-prerm.sh upgrade; fi

%postun
if [ $1 -ge 1 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    systemctl try-restart usbwatch.service usbwatch-web.service >/dev/null 2>&1 || :
fi
# Data is kept on removal. To purge: rm -rf /etc/usbwatch /var/lib/usbwatch /var/log/usbwatch; userdel usbwatch

%files
%license README.md
%doc /usr/share/doc/usbwatch
/usr/bin/usbwatch
/usr/lib/usbwatch
%{_unitdir}/usbwatch.service
%{_unitdir}/usbwatch-web.service
/usr/share/applications/usbwatch.desktop
%dir %attr(0750,root,usbwatch) /etc/usbwatch
%config(noreplace) %attr(0640,root,usbwatch) /etc/usbwatch/usbwatch.conf
%config(noreplace) /etc/logrotate.d/usbwatch

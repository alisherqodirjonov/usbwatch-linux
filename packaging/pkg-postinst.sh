#!/bin/sh
# Shared post-install step for the .deb and .rpm packages: account, folders, database, services.
set -e
NOLOGIN=$(command -v nologin 2>/dev/null || echo /bin/false)
getent group usbwatch >/dev/null 2>&1 || groupadd --system usbwatch
getent passwd usbwatch >/dev/null 2>&1 || useradd --system --gid usbwatch --no-create-home \
    --home-dir /var/lib/usbwatch --shell "$NOLOGIN" --comment "USBWatch web console" usbwatch
chown root:usbwatch /etc/usbwatch /etc/usbwatch/usbwatch.conf
chmod 750 /etc/usbwatch
chmod 640 /etc/usbwatch/usbwatch.conf
# creates the first console user 'admin' with a random password (shown once, and saved to
# /etc/usbwatch/initial-admin-password) unless one exists; change it with: sudo usbwatch passwd
@BINDIR@/usbwatch setup </dev/null
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable usbwatch.service usbwatch-web.service >/dev/null 2>&1
    systemctl restart usbwatch.service usbwatch-web.service
else
    for u in usbwatch usbwatch-web; do
        if command -v update-rc.d >/dev/null 2>&1; then update-rc.d $u defaults >/dev/null
        elif command -v chkconfig >/dev/null 2>&1; then chkconfig --add $u
        fi
        /etc/init.d/$u restart || true
    done
fi
echo "USBWatch console: http://127.0.0.1:8790/  (sudo usbwatch status)"

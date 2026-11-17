#!/bin/sh
# Shared purge step (deb: 'purge'; rpm: run by hand after removal if wanted).
set +e
rm -rf /var/lib/usbwatch /var/log/usbwatch /etc/usbwatch
getent passwd usbwatch >/dev/null 2>&1 && userdel usbwatch
getent group usbwatch >/dev/null 2>&1 && groupdel usbwatch
[ -d /run/systemd/system ] && systemctl daemon-reload
exit 0

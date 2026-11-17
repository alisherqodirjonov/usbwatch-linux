#!/bin/sh
# Shared pre-removal step: stop services; on a real removal (not an upgrade) re-enable blocked devices.
#   pkg-prerm.sh remove|upgrade
set +e
if [ "$1" = remove ] && [ -f /var/lib/usbwatch/usbwatch.db ]; then
    @BINDIR@/usbwatch unblock-all
fi
if [ -d /run/systemd/system ]; then
    if [ "$1" = remove ]; then
        systemctl disable --now usbwatch-web.service usbwatch.service >/dev/null 2>&1
    else
        systemctl stop usbwatch-web.service usbwatch.service >/dev/null 2>&1
    fi
else
    for u in usbwatch-web usbwatch; do
        [ -x /etc/init.d/$u ] && /etc/init.d/$u stop
        if [ "$1" = remove ]; then
            command -v update-rc.d >/dev/null 2>&1 && update-rc.d -f $u remove >/dev/null
            command -v chkconfig >/dev/null 2>&1 && chkconfig --del $u
        fi
    done
fi
exit 0

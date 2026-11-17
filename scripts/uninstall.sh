#!/bin/sh
# USBWatch for Linux - uninstaller.
#   sudo ./scripts/uninstall.sh [--prefix /usr/local] [--purge]
# --purge also deletes the configuration, database, recovery vault, logs and the 'usbwatch' account.
# Any USB device the service blocked is re-enabled first.
set -u

PREFIX=/usr/local
PURGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift 2 ;;
        --purge) PURGE=1; shift ;;
        -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
        *) echo "unknown option $1"; exit 1 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "run as root (sudo $0)"; exit 1; }
BINDIR=$PREFIX/bin
LIBDIR=$PREFIX/lib/usbwatch

if [ -x "$BINDIR/usbwatch" ] && [ -f /var/lib/usbwatch/usbwatch.db ]; then
    echo "==> Re-enabling blocked USB devices"
    "$BINDIR/usbwatch" unblock-all || true
fi

echo "==> Stopping and removing services"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now usbwatch-web.service usbwatch.service 2>/dev/null || true
    rm -f /etc/systemd/system/usbwatch.service /etc/systemd/system/usbwatch-web.service
    systemctl daemon-reload 2>/dev/null || true
fi
for u in usbwatch-web usbwatch; do
    if [ -f /etc/init.d/$u ]; then
        /etc/init.d/$u stop 2>/dev/null || true
        if command -v rc-update >/dev/null 2>&1; then rc-update del $u default 2>/dev/null || true; fi
        if command -v update-rc.d >/dev/null 2>&1; then update-rc.d -f $u remove >/dev/null 2>&1 || true; fi
        if command -v chkconfig >/dev/null 2>&1; then chkconfig --del $u 2>/dev/null || true; fi
        rm -f /etc/init.d/$u /etc/rc?.d/[SK]??$u
    fi
done
rm -f /etc/init.d/usbwatch-common

echo "==> Removing program files"
rm -rf "$LIBDIR" "$PREFIX/share/doc/usbwatch"
rm -f "$BINDIR/usbwatch" /usr/share/applications/usbwatch.desktop /etc/logrotate.d/usbwatch

if [ "$PURGE" = 1 ]; then
    echo "==> Purging configuration, data, vault, logs and the usbwatch account"
    rm -rf /etc/usbwatch /var/lib/usbwatch /var/log/usbwatch
    if getent passwd usbwatch >/dev/null 2>&1; then userdel usbwatch 2>/dev/null || deluser usbwatch 2>/dev/null || true; fi
    if getent group usbwatch >/dev/null 2>&1; then groupdel usbwatch 2>/dev/null || delgroup usbwatch 2>/dev/null || true; fi
else
    echo "Kept /etc/usbwatch, /var/lib/usbwatch and /var/log/usbwatch (use --purge to delete them)."
fi
echo "USBWatch removed."

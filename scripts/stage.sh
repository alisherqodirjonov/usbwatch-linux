#!/bin/sh
# Lay out the installed file tree under a staging root (used by the .deb / .rpm builds).
#   scripts/stage.sh ROOT [PREFIX=/usr] [PYTHON=/usr/bin/python3]
set -eu
umask 022
ROOT=$1
PREFIX=${2:-/usr}
PY=${3:-/usr/bin/python3}
SRC=$(cd "$(dirname "$0")/.." && pwd)
BINDIR=$PREFIX/bin
LIBDIR=$PREFIX/lib/usbwatch
DOCDIR=$PREFIX/share/doc/usbwatch
UNITDIR=${UNITDIR:-/lib/systemd/system}

sub() {
    sed -e "s|@BINDIR@|$BINDIR|g" -e "s|@LIBDIR@|$LIBDIR|g" -e "s|@DOCDIR@|$DOCDIR|g" -e "s|@DATADIR@|/var/lib/usbwatch|g" "$1"
}

rm -rf "$ROOT"
mkdir -p "$ROOT$LIBDIR/usbwatch/static" "$ROOT$BINDIR" "$ROOT$DOCDIR" "$ROOT/etc/usbwatch" \
         "$ROOT$UNITDIR" "$ROOT/etc/init.d" "$ROOT/etc/logrotate.d" "$ROOT$PREFIX/share/applications"
install -m 644 "$SRC"/usbwatch/*.py "$ROOT$LIBDIR/usbwatch/"
install -m 644 "$SRC"/usbwatch/static/* "$ROOT$LIBDIR/usbwatch/static/"
install -m 644 "$SRC/packaging/launcher.py" "$ROOT$LIBDIR/launcher.py"
for s in pkg-postinst.sh pkg-prerm.sh pkg-postrm.sh; do
    sub "$SRC/packaging/$s" > "$ROOT$LIBDIR/$s"
    chmod 755 "$ROOT$LIBDIR/$s"
done
printf '#!/bin/sh\nexec %s -E -s %s/launcher.py "$@"\n' "$PY" "$LIBDIR" > "$ROOT$BINDIR/usbwatch"
chmod 755 "$ROOT$BINDIR/usbwatch"
install -m 640 "$SRC/packaging/usbwatch.conf" "$ROOT/etc/usbwatch/usbwatch.conf"
for u in usbwatch usbwatch-web; do
    sub "$SRC/packaging/systemd/$u.service" > "$ROOT$UNITDIR/$u.service"
    sub "$SRC/packaging/sysvinit/$u" > "$ROOT/etc/init.d/$u"
    chmod 755 "$ROOT/etc/init.d/$u"
done
sub "$SRC/packaging/sysvinit/usbwatch-common" > "$ROOT/etc/init.d/usbwatch-common"
sub "$SRC/packaging/logrotate/usbwatch" > "$ROOT/etc/logrotate.d/usbwatch"
sub "$SRC/packaging/desktop/usbwatch.desktop" > "$ROOT$PREFIX/share/applications/usbwatch.desktop"
install -m 644 "$SRC/README.md" "$SRC"/docs/*.md "$ROOT$DOCDIR/"
echo "staged into $ROOT"

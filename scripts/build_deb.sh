#!/bin/sh
# Build dist/usbwatch_<version>_all.deb with dpkg-deb (no debhelper needed).
set -eu
umask 022
SRC=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$SRC/usbwatch/__init__.py")
ROOT="$SRC/build/deb"
UNITDIR=/lib/systemd/system sh "$SRC/scripts/stage.sh" "$ROOT" /usr /usr/bin/python3 >/dev/null
mkdir -p "$ROOT/DEBIAN"
SIZE=$(du -sk "$ROOT" | cut -f1)
sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE@/$SIZE/" "$SRC/packaging/debian/control" > "$ROOT/DEBIAN/control"
for f in postinst prerm postrm; do install -m 755 "$SRC/packaging/debian/$f" "$ROOT/DEBIAN/$f"; done
install -m 644 "$SRC/packaging/debian/conffiles" "$ROOT/DEBIAN/conffiles"
mkdir -p "$SRC/dist"
OUT="$SRC/dist/usbwatch_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$ROOT" "$OUT" 2>/dev/null || dpkg-deb --build "$ROOT" "$OUT"
echo "built $OUT"

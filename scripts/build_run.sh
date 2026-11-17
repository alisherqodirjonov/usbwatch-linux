#!/bin/sh
# Build dist/usbwatch-<version>.run - one self-extracting file that installs on any supported distro:
#   sudo sh usbwatch-<version>.run [install.sh options]       e.g. --password 'S3cret-pass!'
set -eu
umask 022
SRC=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$SRC/usbwatch/__init__.py")
OUT="$SRC/dist/usbwatch-$VERSION.run"
mkdir -p "$SRC/dist"
cat > "$OUT" <<'EOF'
#!/bin/sh
# USBWatch for Linux - self-extracting installer. Usage: sudo sh $0 [--help | install options]
set -e
[ "$(id -u)" = 0 ] || { echo "Run as root:  sudo sh $0 $*"; exit 1; }
LINE=$(awk '/^__USBWATCH_PAYLOAD__$/ { print NR + 1; exit 0; }' "$0")
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
tail -n +"$LINE" "$0" | gzip -dc | tar -xf - -C "$TMP"
sh "$TMP/usbwatch-linux/scripts/install.sh" "$@"
exit $?
__USBWATCH_PAYLOAD__
EOF
# stage under a fixed name (tar --transform is GNU-only) so the payload always extracts to usbwatch-linux/
STAGE=$(mktemp -d)
mkdir -p "$STAGE/usbwatch-linux"
cp -R "$SRC/usbwatch" "$SRC/packaging" "$SRC/scripts" "$SRC/docs" "$SRC/README.md" "$STAGE/usbwatch-linux/"
find "$STAGE" -name __pycache__ -prune -exec rm -rf {} +
tar -C "$STAGE" -cf - usbwatch-linux | gzip -9 >> "$OUT"
rm -rf "$STAGE"
chmod 755 "$OUT"
echo "built $OUT ($(du -k "$OUT" | cut -f1) KB)"

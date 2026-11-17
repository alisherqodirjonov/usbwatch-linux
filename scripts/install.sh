#!/bin/sh
# USBWatch for Linux - installer (POSIX sh; works with bash, dash, busybox ash).
#
#   sudo ./scripts/install.sh [options]
#
# Options:
#   --prefix DIR          install under DIR (default /usr/local; packages use /usr)
#   --init auto|systemd|openrc|sysvinit|none     service manager (default: detect)
#   --password PW         initial console password for user 'admin'
#   --password-stdin      read it from stdin
#   --bind ADDR           [web] bind for a NEW config file   (default 127.0.0.1)
#   --port N              [web] port for a NEW config file   (default 8790)
#   --allow LIST          [web] allow for a NEW config file  (default "127.0.0.1, ::1")
#   --no-start            install and enable, but do not start the services now
#   --force               install even if the requirements check fails
#
# Without a password option you are asked interactively; in a non-interactive run a random password is
# generated and saved to /etc/usbwatch/initial-admin-password (root only).
set -eu
umask 022

PREFIX=/usr/local
INIT=auto
PW=""
PW_STDIN=0
BIND=""
PORT=""
ALLOW=""
START=1
FORCE=0

die() { echo "error: $*" >&2; exit 1; }
say() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift 2 ;;
        --init) INIT=$2; shift 2 ;;
        --password) PW=$2; shift 2 ;;
        --password-stdin) PW_STDIN=1; shift ;;
        --bind) BIND=$2; shift 2 ;;
        --port) PORT=$2; shift 2 ;;
        --allow) ALLOW=$2; shift 2 ;;
        --no-start) START=0; shift ;;
        --force) FORCE=1; shift ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

[ "$(id -u)" = 0 ] || die "run as root (sudo $0 ...)"
SRC=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$SRC/usbwatch/cli.py" ] || die "cannot find the usbwatch sources next to this script"

BINDIR=$PREFIX/bin
LIBDIR=$PREFIX/lib/usbwatch
DOCDIR=$PREFIX/share/doc/usbwatch
CONFDIR=/etc/usbwatch
DATADIR=/var/lib/usbwatch
LOGDIR=/var/log/usbwatch

# ------------------------------------------------------------------ requirements negotiation
say "Checking requirements"
PY=""
for cand in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6 \
            /usr/libexec/platform-python; do
    p=$(command -v "$cand" 2>/dev/null || true)
    [ -n "$p" ] || continue
    if "$p" -c 'import sys, sqlite3, ctypes; sys.exit(sys.version_info < (3, 6))' 2>/dev/null; then
        PY=$p; break
    fi
done
if [ -z "$PY" ]; then
    echo "Python 3.6+ (with sqlite3 and ctypes) is required. Install it with:"
    echo "  Debian/Ubuntu: apt install python3          RHEL/Rocky/Alma/Fedora: dnf install python3"
    echo "  openSUSE: zypper install python3             Arch: pacman -S python      Alpine: apk add python3"
    exit 1
fi
KREL=$(uname -r)
KMAJ=$(echo "$KREL" | cut -d. -f1)
KMIN=$(echo "$KREL" | cut -d. -f2 | sed 's/[^0-9].*//')
ARCH=$(uname -m)
echo "    python : $PY ($("$PY" -c 'import platform; print(platform.python_version())'))"
echo "    kernel : $KREL   arch: $ARCH"
if [ "$KMAJ" -lt 3 ] || { [ "$KMAJ" -eq 3 ] && [ "$KMIN" -lt 10 ]; }; then
    [ "$FORCE" = 1 ] || die "kernel 3.10 or newer is required (found $KREL); use --force to try anyway"
    echo "    WARNING: kernel older than 3.10 - continuing because of --force"
fi
[ -d /sys/bus/usb ] || echo "    WARNING: /sys/bus/usb not found (container or no USB) - nothing will be monitored"

if [ "$INIT" = auto ]; then
    if [ -d /run/systemd/system ]; then INIT=systemd
    elif command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then INIT=openrc
    elif [ -d /etc/init.d ]; then INIT=sysvinit
    else INIT=none
    fi
fi
echo "    init   : $INIT"

# ------------------------------------------------------------------ account
say "Creating system user/group 'usbwatch'"
NOLOGIN=$(command -v nologin 2>/dev/null || echo /bin/false)
if ! getent group usbwatch >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then groupadd --system usbwatch
    else addgroup -S usbwatch; fi
fi
if ! getent passwd usbwatch >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --gid usbwatch --no-create-home --home-dir "$DATADIR" --shell "$NOLOGIN" \
            --comment "USBWatch web console" usbwatch
    else
        adduser -S -D -H -h "$DATADIR" -s "$NOLOGIN" -G usbwatch -g "USBWatch web console" usbwatch
    fi
fi

# ------------------------------------------------------------------ files
say "Installing to $LIBDIR"
sub() {   # substitute @PLACEHOLDERS@ in a template
    sed -e "s|@BINDIR@|$BINDIR|g" -e "s|@LIBDIR@|$LIBDIR|g" -e "s|@DOCDIR@|$DOCDIR|g" -e "s|@DATADIR@|$DATADIR|g" "$1"
}
rm -rf "$LIBDIR/usbwatch"
mkdir -p "$LIBDIR/usbwatch/static" "$BINDIR" "$DOCDIR"
for f in "$SRC"/usbwatch/*.py; do install -m 644 "$f" "$LIBDIR/usbwatch/"; done
for f in "$SRC"/usbwatch/static/*; do install -m 644 "$f" "$LIBDIR/usbwatch/static/"; done
install -m 644 "$SRC/packaging/launcher.py" "$LIBDIR/launcher.py"
"$PY" -m compileall -q "$LIBDIR/usbwatch" >/dev/null 2>&1 || true
cat > "$BINDIR/usbwatch" <<EOF
#!/bin/sh
exec $PY -E -s $LIBDIR/launcher.py "\$@"
EOF
chmod 755 "$BINDIR/usbwatch"
for f in "$SRC"/README.md "$SRC"/docs/*.md; do
    if [ -f "$f" ]; then install -m 644 "$f" "$DOCDIR/"; fi
done

mkdir -p "$CONFDIR"
if [ ! -f "$CONFDIR/usbwatch.conf" ]; then
    cp "$SRC/packaging/usbwatch.conf" "$CONFDIR/usbwatch.conf"
    if [ -n "$BIND" ]; then sed -i "s|^bind = .*|bind = $BIND|" "$CONFDIR/usbwatch.conf"; fi
    if [ -n "$PORT" ]; then sed -i "s|^port = .*|port = $PORT|" "$CONFDIR/usbwatch.conf"; fi
    if [ -n "$ALLOW" ]; then sed -i "s|^allow = .*|allow = $ALLOW|" "$CONFDIR/usbwatch.conf"; fi
else
    echo "    keeping existing $CONFDIR/usbwatch.conf"
    if [ -n "$BIND$PORT$ALLOW" ]; then echo "    (--bind/--port/--allow only apply to a new config file; edit it by hand)"; fi
fi
chown root:usbwatch "$CONFDIR" "$CONFDIR/usbwatch.conf"
chmod 750 "$CONFDIR"
chmod 640 "$CONFDIR/usbwatch.conf"
if [ -d /etc/logrotate.d ]; then sub "$SRC/packaging/logrotate/usbwatch" > /etc/logrotate.d/usbwatch; fi
if [ -d /usr/share/applications ]; then
    sub "$SRC/packaging/desktop/usbwatch.desktop" > /usr/share/applications/usbwatch.desktop
    chmod 644 /usr/share/applications/usbwatch.desktop
fi

# ------------------------------------------------------------------ database + first console user
say "Initialising data folders and database"
if [ -n "$PW" ]; then
    "$BINDIR/usbwatch" setup --password "$PW"
elif [ "$PW_STDIN" = 1 ]; then
    "$BINDIR/usbwatch" setup --password-stdin
elif [ -t 0 ]; then
    "$BINDIR/usbwatch" setup
else
    "$BINDIR/usbwatch" setup </dev/null
fi

# ------------------------------------------------------------------ autostart
say "Registering services ($INIT)"
case "$INIT" in
    systemd)
        for u in usbwatch usbwatch-web; do
            sub "$SRC/packaging/systemd/$u.service" > /etc/systemd/system/$u.service
            chmod 644 /etc/systemd/system/$u.service
        done
        systemctl daemon-reload
        systemctl enable usbwatch.service usbwatch-web.service
        if [ "$START" = 1 ]; then systemctl restart usbwatch.service usbwatch-web.service; fi
        ;;
    openrc)
        for u in usbwatch usbwatch-web; do
            sub "$SRC/packaging/openrc/$u" > /etc/init.d/$u
            chmod 755 /etc/init.d/$u
            rc-update add $u default >/dev/null
        done
        if [ "$START" = 1 ]; then rc-service usbwatch restart; rc-service usbwatch-web restart; fi
        ;;
    sysvinit)
        sub "$SRC/packaging/sysvinit/usbwatch-common" > /etc/init.d/usbwatch-common
        chmod 644 /etc/init.d/usbwatch-common
        for u in usbwatch usbwatch-web; do
            sub "$SRC/packaging/sysvinit/$u" > /etc/init.d/$u
            chmod 755 /etc/init.d/$u
            if command -v update-rc.d >/dev/null 2>&1; then update-rc.d $u defaults >/dev/null
            elif command -v chkconfig >/dev/null 2>&1; then chkconfig --add $u
            else
                for l in 2 3 4 5; do mkdir -p /etc/rc$l.d; ln -sf ../init.d/$u /etc/rc$l.d/S90$u; done
                for l in 0 1 6; do mkdir -p /etc/rc$l.d; ln -sf ../init.d/$u /etc/rc$l.d/K10$u; done
            fi
        done
        if [ "$START" = 1 ]; then /etc/init.d/usbwatch restart; /etc/init.d/usbwatch-web restart; fi
        ;;
    none)
        echo "    No service manager detected. Start manually:"
        echo "      $BINDIR/usbwatch daemon &    $BINDIR/usbwatch web &"
        ;;
    *) die "unknown --init $INIT" ;;
esac

PORTV=$(sed -n 's/^port *= *//p' "$CONFDIR/usbwatch.conf" | head -1)
BINDV=$(sed -n 's/^bind *= *//p' "$CONFDIR/usbwatch.conf" | head -1 | cut -d, -f1)
if [ "$BINDV" = "0.0.0.0" ]; then BINDV=127.0.0.1; fi
echo
echo "USBWatch installed."
echo "  Console : http://${BINDV:-127.0.0.1}:${PORTV:-8790}/   (user: admin)   or run: usbwatch open"
echo "  Status  : sudo usbwatch status      Requirements: sudo usbwatch doctor"
echo "  Config  : $CONFDIR/usbwatch.conf    Data: $DATADIR    Logs: $LOGDIR"
echo "  Remove  : sudo $SRC/scripts/uninstall.sh [--purge]   (or: sudo make uninstall)"

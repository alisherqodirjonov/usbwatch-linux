"""usbwatch command line.

  usbwatch daemon                 monitoring service (root)            - started by the init system
  usbwatch web                    web console (drops to user usbwatch) - started by the init system
  usbwatch setup                  create folders, database and the first console account (installer)
  usbwatch status                 service health and counters
  usbwatch doctor                 check this machine against the requirements
  usbwatch passwd [USER]          set a console password (creates the user if needed)
  usbwatch users | userdel USER   list / remove console accounts
  usbwatch events [-n N] [-f]     print recent events (add --json or --csv)
  usbwatch devices                list known USB devices
  usbwatch unblock-all            emergency: policy off and re-enable every blocked device
  usbwatch open                   open the console in a browser
"""
import os
import sys
import json
import time
import argparse
import platform
import getpass

from . import VERSION, MIN_PYTHON, MIN_KERNEL, db
from .config import Config, CONF_FILE

GROUP = "usbwatch"


def need_root():
    if os.geteuid() != 0:
        sys.exit("This command needs root (sudo).")


def _cfg(a):
    return Config(a.config)


def _db(cfg, must_exist=True):
    if must_exist and not os.path.exists(cfg.db_path):
        sys.exit("No database at %s yet. Is USBWatch installed? (sudo usbwatch setup)" % cfg.db_path)
    try:
        return db.init(cfg.db_path)
    except Exception as e:
        sys.exit("Cannot open %s: %s (try sudo)" % (cfg.db_path, e))


# ------------------------------------------------------------------ services
def cmd_daemon(a):
    from . import daemon
    if os.geteuid() != 0:
        print("WARNING: not root - devices cannot be blocked and process attribution is off.", file=sys.stderr)
    return daemon.main(_cfg(a))


def cmd_web(a):
    from . import web
    return web.main(_cfg(a), user=a.user)


# ------------------------------------------------------------------ setup
def _chown(path, uid, gid, mode):
    try:
        os.chown(path, uid, gid)
        os.chmod(path, mode)
    except OSError as e:
        print("warning: %s: %s" % (path, e), file=sys.stderr)


def cmd_setup(a):
    need_root()
    import grp
    import secrets
    cfg = _cfg(a)
    try:
        gid = grp.getgrnam(GROUP).gr_gid
    except KeyError:
        sys.exit("Group %r is missing - the installer creates it (useradd --system usbwatch)." % GROUP)
    os.umask(0o007)
    for d, mode in ((cfg.data_dir, 0o2770), (cfg.log_dir, 0o2750), (os.path.dirname(cfg.path), 0o750)):
        os.makedirs(d, exist_ok=True)
        _chown(d, 0, gid, mode)
    os.makedirs(cfg.vault_dir, exist_ok=True)
    _chown(cfg.vault_dir, 0, 0, 0o700)
    c = db.init(cfg.db_path)
    for f in (cfg.db_path, cfg.db_path + "-wal", cfg.db_path + "-shm"):
        if os.path.exists(f):
            _chown(f, 0, gid, 0o660)
    if os.path.exists(cfg.path):
        _chown(cfg.path, 0, gid, 0o640)
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 and not a.no_password:
        pw = a.password or (sys.stdin.readline().strip() if a.password_stdin else "")
        if not pw and sys.stdin.isatty() and not a.password_stdin:
            pw = _ask_new_password(allow_empty=True)
        initial = ""
        if not pw:
            pw = secrets.token_urlsafe(12)
            initial = os.path.join(os.path.dirname(cfg.path), "initial-admin-password")
            fd = os.open(initial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(pw + "\n")
            db.set_state(c, "initial_pw", "set")
        elif len(pw) < db.MIN_PASSWORD:
            sys.exit("Password must have at least %d characters." % db.MIN_PASSWORD)
        db.set_password(c, a.user, pw)
        db.audit(c, "setup", "created console user", a.user)
        c.commit()
        print("=" * 66)
        print("  Console user: %s" % a.user)
        if initial:
            print("  Initial password: %s" % pw)
            print("  (also saved to %s - change it after signing in)" % initial)
        print("=" * 66)
    c.commit()
    c.close()
    print("Setup complete. Config: %s  Data: %s" % (cfg.path, cfg.data_dir))
    return 0


def _ask_new_password(allow_empty=False):
    while True:
        pw = getpass.getpass("New console password%s: " % (" (Enter = generate one)" if allow_empty else ""))
        if not pw and allow_empty:
            return ""
        if len(pw) < db.MIN_PASSWORD:
            print("Use at least %d characters." % db.MIN_PASSWORD)
            continue
        if pw != getpass.getpass("Repeat: "):
            print("Passwords differ.")
            continue
        return pw


def cmd_passwd(a):
    need_root()
    cfg = _cfg(a)
    c = _db(cfg)
    pw = sys.stdin.readline().rstrip("\n") if a.password_stdin else _ask_new_password()
    if len(pw) < db.MIN_PASSWORD:
        sys.exit("Password must have at least %d characters." % db.MIN_PASSWORD)
    new = not c.execute("SELECT 1 FROM users WHERE name=?", (a.name,)).fetchone()
    db.set_password(c, a.name, pw)
    db.audit(c, "cli", "created console user" if new else "changed password", a.name)
    if db.get_state(c, "initial_pw") == "set":
        db.set_state(c, "initial_pw", "changed")
    c.commit()
    print(("User %s created." if new else "Password for %s changed.") % a.name)
    return 0


def cmd_users(a):
    c = _db(_cfg(a))
    for r in db.rows(c, "SELECT name, created, last_login FROM users ORDER BY name"):
        print("%-20s created %s   last sign-in %s" % (r["name"], db.now_str(r["created"]),
                                                      db.now_str(r["last_login"]) if r["last_login"] else "never"))
    return 0


def cmd_userdel(a):
    need_root()
    c = _db(_cfg(a))
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] <= 1:
        sys.exit("Refusing to delete the last console user.")
    n = c.execute("DELETE FROM users WHERE name=?", (a.name,)).rowcount
    c.execute("DELETE FROM sessions WHERE user=?", (a.name,))
    db.audit(c, "cli", "deleted console user", a.name)
    c.commit()
    print("Deleted." if n else "No such user.")
    return 0 if n else 1


# ------------------------------------------------------------------ status / queries
def cmd_status(a):
    cfg = _cfg(a)
    c = _db(cfg)
    try:
        st = json.loads(db.get_state(c, "daemon", "{}"))
    except ValueError:
        st = {}
    alive = bool(st) and time.time() - st.get("heartbeat", 0) < 30
    print("USBWatch %s" % VERSION)
    print("Config      : %s%s" % (cfg.path, "" if cfg.loaded else " (not found, using defaults)"))
    print("Data        : %s" % cfg.data_dir)
    print("Daemon      : %s" % ("running (pid %s, since %s)" % (st.get("pid"), db.now_str(st.get("started")))
                                if alive else "NOT running" + (" (last seen %s)" % db.now_str(st["heartbeat"])
                                                               if st.get("heartbeat") else "")))
    if st:
        print("  root      : %s" % st.get("root"))
        print("  fanotify  : %s%s" % (st.get("fanotify"), " (+exec events)" if st.get("exec_events") else ""))
        print("  netlink   : %s" % st.get("netlink"))
        print("  watches   : %s of %s" % (st.get("watches"), st.get("inotify_limit")))
    s = db.typed_settings(c)
    print("Policy      : mode=%s scope=%s whitelist=%d blacklist=%d" % (
        s["mode"], s["policy_scope"], c.execute("SELECT COUNT(*) FROM policy WHERE kind='allow'").fetchone()[0],
        c.execute("SELECT COUNT(*) FROM policy WHERE kind='block'").fetchone()[0]))
    print("Console     : %s://%s:%d/  (allow: %s)" % ("https" if cfg.get("web", "tls_cert") else "http",
                                                   cfg.bind_addresses()[0], cfg.getint("web", "port"),
                                                   ", ".join(cfg.getlist("web", "allow"))))
    print("Devices     : %d known, %d connected, %d blocked" % (
        c.execute("SELECT COUNT(*) FROM devices").fetchone()[0], c.execute("SELECT COUNT(*) FROM attached").fetchone()[0],
        c.execute("SELECT COUNT(*) FROM blocked").fetchone()[0]))
    for m in db.rows(c, "SELECT * FROM mounts"):
        print("  mounted   : %s  %s  %s  %s" % (m["mount"], m["label"] or "-", m["fs"], m["serial"]))
    print("Events      : %d total, %d in the last 24 h" % (
        c.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        c.execute("SELECT COUNT(*) FROM events WHERE epoch>?", (time.time() - 86400,)).fetchone()[0]))
    return 0 if alive else 3


EV_COLS = ("ts", "action", "direction", "serial", "path", "dest", "size", "user", "login", "process", "pid",
           "cmdline", "sha256", "detail")


def _print_events(rows, a):
    import csv
    if a.json:
        for r in rows:
            print(json.dumps({k: v for k, v in r.items() if v not in (None, "")}, ensure_ascii=False))
    elif a.csv:
        w = csv.writer(sys.stdout)
        for r in rows:
            w.writerow(["" if r.get(k) is None else r.get(k) for k in EV_COLS])
    else:
        for r in rows:
            who = r["user"] + ("(%s)" % r["login"] if r["login"] else "")
            proc = "%s[%s]" % (r["process"], r["pid"]) if r["process"] else ""
            extra = " -> " + r["dest"] if r["dest"] else ""
            print("%s  %-17s %-8s %-28s %s%s  %s %s" % (r["ts"], r["action"], r["direction"], r["serial"][:28],
                                                       r["path"], extra, who, proc))
        sys.stdout.flush()


def cmd_events(a):
    c = _db(_cfg(a))
    where, args = "1=1", []
    if a.action:
        where += " AND action=?"
        args.append(a.action)
    if a.serial:
        where += " AND serial=?"
        args.append(a.serial.upper())
    if a.csv:
        import csv
        csv.writer(sys.stdout).writerow(EV_COLS)
    rows = db.rows(c, "SELECT * FROM events WHERE %s ORDER BY id DESC LIMIT ?" % where, args + [a.n])[::-1]
    _print_events(rows, a)
    last = rows[-1]["id"] if rows else c.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
    while a.follow:
        time.sleep(1)
        rows = db.rows(c, "SELECT * FROM events WHERE %s AND id>? ORDER BY id" % where, args + [last])
        if rows:
            _print_events(rows, a)
            last = rows[-1]["id"]
    return 0


def cmd_devices(a):
    c = _db(_cfg(a))
    rows = db.rows(c, "SELECT d.*, p.kind list, (SELECT COUNT(*) FROM attached x WHERE x.serial=d.serial) connected "
                      "FROM devices d LEFT JOIN policy p ON p.serial=d.serial ORDER BY d.last DESC")
    if a.json:
        print(json.dumps(rows, indent=1, ensure_ascii=False))
        return 0
    print("%-32s %-9s %-34s %-7s %-19s %-19s %s" % ("SERIAL", "VID:PID", "NAME", "STORAGE", "FIRST", "LAST", "STATE"))
    for r in rows:
        state = ("connected " if r["connected"] else "") + ({"allow": "whitelisted", "block": "blacklisted"}.get(r["list"]) or "")
        print("%-32s %-9s %-34s %-7s %-19s %-19s %s" % (r["serial"][:32], "%s:%s" % (r["vid"], r["pid"]),
                                                       (r["name"] or "")[:34], "yes" if r["storage"] else "",
                                                       r["first"] or "", r["last"] or "", state))
    return 0


def cmd_unblock_all(a):
    need_root()
    from . import sysusb
    c = _db(_cfg(a))
    db.set_setting(c, "mode", "off")
    n = 0
    for serial, handle in c.execute("SELECT serial, handle FROM blocked").fetchall():
        n += sysusb.set_enabled(handle, True)
    c.execute("DELETE FROM blocked")
    for h, dev in sysusb.usb_devices().items():         # also anything deauthorized outside our records
        if not dev["authorized"] and sysusb.set_enabled(h, True):
            n += 1
    db.audit(c, "cli", "unblock-all", "policy mode set to off, %d device(s) re-enabled" % n)
    c.commit()
    print("Policy mode set to OFF; %d device(s) re-enabled." % n)
    return 0


def cmd_open(a):
    import subprocess
    cfg = _cfg(a)
    host = cfg.bind_addresses()[0]
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    url = "%s://%s:%d/" % ("https" if cfg.get("web", "tls_cert") else "http",
                           "[%s]" % host if ":" in host else host, cfg.getint("web", "port"))
    print(url)
    for opener in ("xdg-open", "gio", "sensible-browser", "x-www-browser"):
        try:
            args = [opener, "open", url] if opener == "gio" else [opener, url]
            subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return 0
        except OSError:
            continue
    print("No browser launcher found; open the URL above.")
    return 0


# ------------------------------------------------------------------ doctor
def _kernel_tuple():
    import re
    m = re.match(r"(\d+)\.(\d+)", platform.release())
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _init_system():
    if os.path.isdir("/run/systemd/system"):
        return "systemd"
    if os.path.exists("/sbin/openrc-run") or os.path.exists("/usr/sbin/openrc-run") or os.path.isdir("/run/openrc"):
        return "openrc"
    if os.path.exists("/etc/init.d"):
        return "sysvinit"
    return "unknown"


def _os_release():
    out = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                out[k] = v.strip('"')
    except OSError:
        pass
    return out


def cmd_doctor(a):
    import sqlite3
    from . import kernel as K
    results = []

    def check(name, ok, detail, required=True):
        results.append((("OK  " if ok else ("FAIL" if required else "WARN")), name, detail))

    osr = _os_release()
    check("distribution", True, "%s (%s)" % (osr.get("PRETTY_NAME", "unknown"), osr.get("ID_LIKE", osr.get("ID", ""))))
    check("architecture", True, "%s - pure Python, any ISA is supported" % platform.machine())
    kv = _kernel_tuple()
    check("kernel >= %d.%d" % MIN_KERNEL, kv >= MIN_KERNEL, platform.release())
    check("python >= %d.%d" % MIN_PYTHON, sys.version_info[:2] >= MIN_PYTHON, platform.python_version())
    sv = tuple(int(x) for x in sqlite3.sqlite_version.split(".")[:2])
    check("sqlite >= 3.7 (WAL)", sv >= (3, 7), sqlite3.sqlite_version)
    check("libc", True, " ".join(platform.libc_ver()) or "musl/unknown")
    check("sysfs USB bus", os.path.isdir("/sys/bus/usb/devices"), "/sys/bus/usb/devices")
    check("/proc/self/mounts", os.path.exists("/proc/self/mounts"), "")
    try:
        K.Inotify().close()
        check("inotify", True, "max_user_watches=%d" % K.inotify_limit())
    except Exception as e:
        check("inotify", False, str(e))
    if os.geteuid() == 0:
        try:
            f = K.Fanotify()
            f.close()
            check("fanotify (process attribution)", True, "exec events need kernel >= 5.0: %s" %
                  ("yes" if kv >= (5, 0) else "no"), required=False)
        except Exception as e:
            check("fanotify (process attribution)", False, "%s - file events will not name the process" % e,
                  required=False)
    else:
        check("fanotify (process attribution)", True, "not tested (run doctor as root)", required=False)
    try:
        import socket
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, K.NETLINK_KOBJECT_UEVENT)
        s.bind((0, 1))
        s.close()
        check("netlink uevents (instant blocking)", True, "")
    except Exception as e:
        check("netlink uevents (instant blocking)", False, "%s - falls back to 1 s polling" % e, required=False)
    init = _init_system()
    check("init system", init != "unknown", init, required=False)
    check("journalctl or kern.log (history)", any(os.path.exists(p) for p in
          ("/usr/bin/journalctl", "/bin/journalctl", "/var/log/kern.log", "/var/log/messages", "/var/log/syslog")),
          "", required=False)
    check("running as root", os.geteuid() == 0, "needed for blocking and fanotify", required=False)
    for st, name, detail in results:
        print("[%s] %-38s %s" % (st, name, detail))
    return 1 if any(r[0] == "FAIL" for r in results) else 0


# ------------------------------------------------------------------ main
def main(argv=None):
    if sys.version_info[:2] < MIN_PYTHON:
        sys.exit("USBWatch needs Python %d.%d or newer." % MIN_PYTHON)
    ap = argparse.ArgumentParser(prog="usbwatch", description="USBWatch for Linux %s - USB device and file audit" % VERSION)
    ap.add_argument("-c", "--config", default=CONF_FILE, help="config file (default %(default)s)")
    ap.add_argument("-V", "--version", action="version", version="usbwatch " + VERSION)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("daemon", help="run the monitoring service in the foreground (root)")
    w = sub.add_parser("web", help="run the web console in the foreground")
    w.add_argument("--user", default="usbwatch", help="user to switch to when started as root (default usbwatch)")
    s = sub.add_parser("setup", help="create folders, database and the first console user (root)")
    s.add_argument("--user", default="admin")
    s.add_argument("--password", help="initial console password (default: ask, or generate one)")
    s.add_argument("--password-stdin", action="store_true", help="read the initial password from stdin")
    s.add_argument("--no-password", action="store_true", help="do not create a console user now")
    sub.add_parser("status", help="show service health")
    sub.add_parser("doctor", help="check this system against the requirements")
    p = sub.add_parser("passwd", help="set a console password (root)")
    p.add_argument("name", nargs="?", default="admin")
    p.add_argument("--password-stdin", action="store_true")
    sub.add_parser("users", help="list console users")
    u = sub.add_parser("userdel", help="delete a console user (root)")
    u.add_argument("name")
    e = sub.add_parser("events", help="print recent events")
    e.add_argument("-n", type=int, default=50)
    e.add_argument("-f", "--follow", action="store_true")
    e.add_argument("--action")
    e.add_argument("--serial")
    e.add_argument("--json", action="store_true")
    e.add_argument("--csv", action="store_true")
    d = sub.add_parser("devices", help="list known USB devices")
    d.add_argument("--json", action="store_true")
    sub.add_parser("unblock-all", help="policy off + re-enable every blocked USB device (root)")
    sub.add_parser("open", help="open the web console in a browser").set_defaults()
    sub.add_parser("gui", help="same as 'open'")
    a = ap.parse_args(argv)
    fn = {"daemon": cmd_daemon, "web": cmd_web, "setup": cmd_setup, "status": cmd_status, "doctor": cmd_doctor,
          "passwd": cmd_passwd, "users": cmd_users, "userdel": cmd_userdel, "events": cmd_events,
          "devices": cmd_devices, "unblock-all": cmd_unblock_all, "open": cmd_open, "gui": cmd_open}.get(a.cmd)
    if not fn:
        ap.print_help()
        return 2
    try:
        return fn(a) or 0
    except KeyboardInterrupt:
        return 130

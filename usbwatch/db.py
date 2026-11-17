"""SQLite storage shared by the root daemon and the unprivileged web console.

The data directory is root:usbwatch, mode 2770 (setgid), and both processes run with umask 007,
so the database, its -wal and -shm files are always group read/write.
SQL stays within SQLite 3.22 (Ubuntu 18.04): no UPSERT, no window functions.
"""
import os
import time
import json
import hashlib
import secrets
import sqlite3
import datetime as dt

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS state(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt TEXT, hash TEXT, created REAL, changed REAL,
    last_login REAL);
CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY, user TEXT, ip TEXT, created REAL, expires REAL);
CREATE TABLE IF NOT EXISTS devices(serial TEXT PRIMARY KEY, vid TEXT, pid TEXT, vendor TEXT, product TEXT,
    name TEXT, classes TEXT, storage INTEGER DEFAULT 0, port TEXT, speed TEXT, first TEXT, last TEXT,
    removed TEXT, times INTEGER DEFAULT 0, total INTEGER, label TEXT, fs TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, epoch REAL, category TEXT,
    action TEXT, direction TEXT DEFAULT '', serial TEXT DEFAULT '', mount TEXT DEFAULT '', path TEXT DEFAULT '',
    dest TEXT DEFAULT '', size INTEGER, user TEXT DEFAULT '', login TEXT DEFAULT '', process TEXT DEFAULT '',
    pid INTEGER, cmdline TEXT DEFAULT '', sha256 TEXT DEFAULT '', detail TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ev_epoch ON events(epoch);
CREATE INDEX IF NOT EXISTS ev_serial ON events(serial, id);
CREATE INDEX IF NOT EXISTS ev_action ON events(action, id);
CREATE TABLE IF NOT EXISTS mounts(mount TEXT PRIMARY KEY, serial TEXT, label TEXT, fs TEXT, uuid TEXT,
    source TEXT, total INTEGER, free INTEGER, watched INTEGER, files INTEGER, ts REAL);
CREATE TABLE IF NOT EXISTS attached(handle TEXT PRIMARY KEY, serial TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS snapshot(serial TEXT, rel TEXT, size INTEGER, PRIMARY KEY(serial, rel));
CREATE TABLE IF NOT EXISTS vault(id INTEGER PRIMARY KEY AUTOINCREMENT, serial TEXT, rel TEXT, path TEXT,
    vpath TEXT, size INTEGER, ts TEXT, sha256 TEXT);
CREATE TABLE IF NOT EXISTS blocked(serial TEXT PRIMARY KEY, handle TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS policy(serial TEXT PRIMARY KEY, kind TEXT, name TEXT, note TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY AUTOINCREMENT, cmd TEXT, args TEXT, user TEXT,
    created REAL, done REAL, ok INTEGER, result TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, who TEXT, ip TEXT,
    action TEXT, detail TEXT);
"""

MODES = ("off", "blacklist", "whitelist")
SCOPES = ("storage", "storage+mtp", "all")
DEFAULT_IGNORE = ("tracker-miner-fs, tracker-miner-fs-3, tracker-extract, tracker-extract-3, localsearch-3, "
                  "localsearch-extractor-3, gvfsd-metadata, gvfs-udisks2-volume-monitor, baloo_file, "
                  "baloo_file_extractor, nautilus-thumbnailer, gnome-thumbnail-factory, ffmpegthumbnailer, "
                  "tumblerd, kded5, kded6, updatedb, mlocate, plocate, udisksd")

# UI-editable settings: key -> (default, kind, lo, hi)
DEFAULTS = {
    "mode": ("off", "choice", MODES, None),
    "policy_scope": ("storage", "choice", SCOPES, None),
    "vault_on": ("0", "bool", None, None),
    "vault_max_mb": ("100", "int", 1, 10240),
    "vault_cap_gb": ("5", "int", 1, 10240),
    "hash_max_mb": ("0", "int", 0, 102400),
    "log_reads": ("1", "bool", None, None),
    "log_exec": ("1", "bool", None, None),
    "read_dedup_s": ("30", "int", 0, 86400),
    "ignore_processes": (DEFAULT_IGNORE, "text", None, 4000),
    "retention_days": ("365", "int", 1, 3650),
}

PBKDF2_ROUNDS = 200000
MIN_PASSWORD = 10


def now_str(t=None):
    return dt.datetime.fromtimestamp(t if t is not None else time.time()).strftime("%Y-%m-%d %H:%M:%S")


def connect(path):
    c = sqlite3.connect(path, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=30000")
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def init(path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    c = connect(path)
    c.executescript(SCHEMA)
    c.commit()
    return c


def rows(c, sql, args=()):
    return [dict(r) for r in c.execute(sql, args).fetchall()]


def one(c, sql, args=()):
    r = c.execute(sql, args).fetchone()
    return dict(r) if r else None


# ---------- settings / state ----------
def get_setting(c, k):
    r = c.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return r[0] if r else DEFAULTS[k][0]


def all_settings(c):
    out = {k: d[0] for k, d in DEFAULTS.items()}
    out.update({r[0]: r[1] for r in c.execute("SELECT k,v FROM settings") if r[0] in DEFAULTS})
    return out


def typed_settings(c):
    out = {}
    for k, v in all_settings(c).items():
        kind = DEFAULTS[k][1]
        if kind == "bool":
            out[k] = v == "1"
        elif kind == "int":
            try:
                out[k] = int(v)
            except ValueError:
                out[k] = int(DEFAULTS[k][0])
        else:
            out[k] = v
    return out


def validate_setting(k, v):
    """Returns the string to store, or raises ValueError."""
    if k not in DEFAULTS:
        raise ValueError("unknown setting %s" % k)
    _d, kind, lo, hi = DEFAULTS[k]
    if kind == "bool":
        return "1" if v in (True, 1, "1", "true", "yes", "on") else "0"
    if kind == "int":
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise ValueError("%s must be a number" % k)
        if not lo <= n <= hi:
            raise ValueError("%s must be between %d and %d" % (k, lo, hi))
        return str(n)
    if kind == "choice":
        if v not in lo:
            raise ValueError("%s must be one of %s" % (k, ", ".join(lo)))
        return v
    v = str(v if v is not None else "")
    if len(v) > hi:
        raise ValueError("%s is too long" % k)
    return v


def set_setting(c, k, v):
    c.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, validate_setting(k, v)))
    bump(c, "policy_rev")


def get_state(c, k, default=""):
    r = c.execute("SELECT v FROM state WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


def set_state(c, k, v):
    c.execute("INSERT OR REPLACE INTO state VALUES(?,?)", (k, v if isinstance(v, str) else json.dumps(v)))


def bump(c, k):
    """Revision counter the daemon polls to notice policy/settings changes made by the console."""
    set_state(c, k, str(int(get_state(c, k, "0") or 0) + 1))


# ---------- users / passwords ----------
def hash_pw(pw, salt_hex):
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt_hex), PBKDF2_ROUNDS).hex()


def set_password(c, user, pw):
    salt = secrets.token_bytes(16).hex()
    t = time.time()
    if c.execute("SELECT 1 FROM users WHERE name=?", (user,)).fetchone():
        c.execute("UPDATE users SET salt=?, hash=?, changed=? WHERE name=?", (salt, hash_pw(pw, salt), t, user))
    else:
        c.execute("INSERT INTO users(name,salt,hash,created,changed) VALUES(?,?,?,?,?)",
                  (user, salt, hash_pw(pw, salt), t, t))
    c.execute("DELETE FROM sessions WHERE user=?", (user,))


def check_password(c, user, pw):
    import hmac
    r = c.execute("SELECT salt, hash FROM users WHERE name=?", (user,)).fetchone()
    if not r:
        hash_pw(pw, "00" * 16)                          # same work for unknown users (no timing oracle)
        return False
    return hmac.compare_digest(hash_pw(pw, r[0]), r[1])


def audit(c, who, action, detail="", ip=""):
    c.execute("INSERT INTO audit(ts,who,ip,action,detail) VALUES(?,?,?,?,?)",
              (time.time(), who, ip, action, (detail or "")[:2000]))


# ---------- events ----------
EVENT_FIELDS = ("ts", "epoch", "category", "action", "direction", "serial", "mount", "path", "dest", "size",
                "user", "login", "process", "pid", "cmdline", "sha256", "detail")


def insert_event(c, e):
    cur = c.execute("INSERT INTO events(%s) VALUES(%s)" % (",".join(EVENT_FIELDS), ",".join("?" * len(EVENT_FIELDS))),
                    tuple(e.get(k, "" if k not in ("size", "pid", "epoch") else None) for k in EVENT_FIELDS))
    return cur.lastrowid

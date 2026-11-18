"""Web console (runs as the unprivileged 'usbwatch' user).

Exposure is controlled only by the root-owned config file:
  * listens on 127.0.0.1 by default ([web] bind)
  * drops every TCP connection whose peer is not in [web] allow (loopback is always allowed)
  * rejects requests whose Host header is not a known name (DNS-rebinding protection)
  * optional TLS ([web] tls_cert / tls_key)
Auth: PBKDF2-SHA256 passwords, random session tokens stored hashed, HttpOnly + SameSite=Strict cookie,
a custom header + Origin check on every state-changing request, lock-out after repeated failures.
"""
import os
import io
import csv
import sys
import json
import time
import hmac
import socket
import secrets
import hashlib
import logging
import ipaddress
import threading
import socketserver
import http.server
import datetime as dt
from urllib.parse import urlsplit, parse_qs, quote

from . import VERSION, db

log = logging.getLogger("usbwatch.web")
HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = {"app.js": "application/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8",
          "index.html": "text/html; charset=utf-8"}
COOKIE = "uw_session"
MAX_BODY = 1 << 20
COMMANDS = ("restore", "refresh_history", "rescan", "unmount", "force_block")
ACTIONS = ("Connected", "Disconnected", "Mounted", "Unmounted", "Created", "Modified", "Read", "Executed",
           "Deleted", "Renamed/Moved", "Deleted (offline)", "Restored", "Blocked", "Block failed", "Unblocked",
           "Unblock failed", "Policy applied", "Watch limit", "Event overflow", "Service started", "Service stopped")


class HttpError(Exception):
    def __init__(self, status, detail):
        Exception.__init__(self, detail)
        self.status, self.detail = status, detail


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def s(v, n=4096):
    return ("" if v is None else str(v))[:n]


class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.nets = cfg.allow_networks()
        self.hosts = cfg.allowed_hosts()
        self.any_host = "*" in self.hosts
        self.session_secs = max(300, cfg.getint("web", "session_hours") * 3600)
        self.max_fails = max(3, cfg.getint("web", "max_failed_logins"))
        self.fails, self.fail_lock = {}, threading.Lock()
        self.local = threading.local()
        self.tls = bool(cfg.get("web", "tls_cert"))

    def conn(self):
        c = getattr(self.local, "c", None)
        if c is None:
            c = self.local.c = db.connect(self.cfg.db_path)
        return c

    # --- network policy ---
    def client_allowed(self, ip):
        try:
            a = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            return False
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        return any(a.version == n.version and a in n for n in self.nets)

    def host_allowed(self, host):
        if self.any_host:
            return True
        h = (host or "").strip().lower()
        if h.startswith("["):
            h = h[:h.find("]") + 1]
        elif h.count(":") == 1:
            h = h.split(":", 1)[0]
        return h in self.hosts

    # --- throttling ---
    def throttle(self, ip, fail=False):
        t = time.time()
        with self.fail_lock:
            lst = [x for x in self.fails.get(ip, []) if t - x < 600]
            if fail:
                lst.append(t)
            self.fails[ip] = lst
            if len(lst) >= self.max_fails:
                raise HttpError(429, "Too many failed attempts. Try again in 10 minutes.")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, addr, handler, app, ssl_ctx=None):
        self.address_family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        self.app, self.ssl_ctx = app, ssl_ctx
        http.server.HTTPServer.__init__(self, addr, handler)

    def verify_request(self, request, client_address):
        if self.app.client_allowed(client_address[0]):
            return True
        log.warning("refused connection from %s (not in [web] allow)", client_address[0])
        return False

    def handle_error(self, request, client_address):
        log.debug("connection from %s failed: %s", client_address[0], sys.exc_info()[1])

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.ssl_ctx:                                # handshake happens in the handler thread
            sock = self.ssl_ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "USBWatch"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 60

    def setup(self):
        if self.server.ssl_ctx:
            self.request.settimeout(self.timeout)
            self.request.do_handshake()
        http.server.BaseHTTPRequestHandler.setup(self)

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.client_address[0], fmt % args)

    @property
    def app(self):
        return self.server.app

    @property
    def ip(self):
        return self.client_address[0]

    # --- responses ---
    def _headers(self, status, ctype, length, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; "
                         "base-uri 'none'")
        self.send_header("Cache-Control", "no-store")
        if self.app.tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def send_json(self, obj, status=200, extra=None):
        body = json.dumps(obj, default=str).encode()
        self._headers(status, "application/json", len(body), extra)
        self.wfile.write(body)

    def send_bytes(self, body, ctype, extra=None):
        self._headers(200, ctype, len(body), extra)
        if self.command != "HEAD":
            self.wfile.write(body)

    # --- request plumbing ---
    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise HttpError(413, "Request too large")
        raw = self.rfile.read(n) if n else b"{}"
        try:
            v = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            raise HttpError(400, "Invalid JSON")
        if not isinstance(v, dict):
            raise HttpError(400, "Expected a JSON object")
        return v

    def cookie(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return v
        return ""

    def session(self):
        tok = self.cookie()
        if not tok:
            raise HttpError(401, "Not signed in")
        c = self.app.conn()
        row = db.one(c, "SELECT user, expires FROM sessions WHERE h=?", (sha(tok),))
        if not row or row["expires"] < time.time():
            raise HttpError(401, "Not signed in")
        if not db.one(c, "SELECT 1 x FROM users WHERE name=?", (row["user"],)):
            raise HttpError(401, "Not signed in")
        c.execute("UPDATE sessions SET expires=? WHERE h=?", (time.time() + self.app.session_secs, sha(tok)))
        c.commit()
        return row["user"]

    def csrf(self):
        if self.headers.get("X-Requested-With") != "usbwatch":
            raise HttpError(403, "Missing request header")
        origin = self.headers.get("Origin")
        if origin and origin != "null" and not self.app.host_allowed(urlsplit(origin).netloc):
            raise HttpError(403, "Cross-origin request refused")

    def handle_any(self):
        try:
            if not self.app.host_allowed(self.headers.get("Host")):
                raise HttpError(421, "Unknown host name. Add it to [web] allowed_hosts in the config file.")
            u = urlsplit(self.path)
            q = {k: v[-1] for k, v in parse_qs(u.query).items()}
            self.route(self.command, u.path, q)
        except HttpError as e:
            self.send_json({"detail": e.detail}, e.status)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            log.exception("%s %s", self.command, self.path)
            try:
                self.send_json({"detail": "Internal error: %s" % e}, 500)
            except Exception:
                pass

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = handle_any

    # --- routing ---
    def route(self, method, path, q):
        if method in ("GET", "HEAD"):
            if path in ("/", "/index.html"):
                return self.static("index.html")
            if path.startswith("/static/"):
                return self.static(path[8:])
        if path == "/api/login" and method == "POST":
            return self.login()
        if not path.startswith("/api/"):
            raise HttpError(404, "Not found")
        user = self.session()
        if method not in ("GET", "HEAD"):
            self.csrf()
        key = (method, path)
        handlers = {
            ("GET", "/api/me"): self.me, ("POST", "/api/logout"): self.logout,
            ("POST", "/api/password"): self.password, ("GET", "/api/summary"): self.summary,
            ("GET", "/api/devices"): self.devices, ("GET", "/api/events"): self.events,
            ("GET", "/api/events.csv"): self.events_csv, ("GET", "/api/deleted"): self.deleted,
            ("GET", "/api/policy"): self.get_policy, ("POST", "/api/policy"): self.set_policy,
            ("GET", "/api/settings"): self.get_settings, ("PUT", "/api/settings"): self.put_settings,
            ("GET", "/api/audit"): self.audit_log, ("GET", "/api/commands"): self.commands,
            ("POST", "/api/commands"): self.add_command, ("GET", "/api/status"): self.status,
        }
        fn = handlers.get(key)
        if not fn:
            raise HttpError(404, "Not found")
        return fn(user, q)

    def static(self, name):
        if name not in STATIC:
            raise HttpError(404, "Not found")
        with open(os.path.join(HERE, "static", name), "rb") as f:
            self.send_bytes(f.read(), STATIC[name])

    def audit(self, user, action, detail=""):
        c = self.app.conn()
        db.audit(c, user, action, detail, self.ip)
        c.commit()

    # --- auth ---
    def login(self):
        self.csrf()
        self.app.throttle(self.ip)
        b = self.body()
        user, pw = s(b.get("user"), 64).strip() or "admin", s(b.get("password"), 256)
        c = self.app.conn()
        if not db.check_password(c, user, pw):
            self.app.throttle(self.ip, fail=True)
            self.audit(user, "sign-in failed")
            raise HttpError(401, "Wrong user name or password")
        tok = secrets.token_urlsafe(32)
        t = time.time()
        c.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (sha(tok), user, self.ip, t, t + self.app.session_secs))
        c.execute("UPDATE users SET last_login=? WHERE name=?", (t, user))
        c.commit()
        self.audit(user, "signed in")
        cookie = "%s=%s; Path=/; HttpOnly; SameSite=Strict%s" % (COOKIE, tok, "; Secure" if self.app.tls else "")
        self.send_json({"ok": True}, extra={"Set-Cookie": cookie})

    def logout(self, user, _q):
        c = self.app.conn()
        c.execute("DELETE FROM sessions WHERE h=?", (sha(self.cookie()),))
        c.commit()
        self.audit(user, "signed out")
        self.send_json({"ok": True}, extra={"Set-Cookie": "%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" % COOKIE})

    def me(self, user, _q):
        c = self.app.conn()
        self.send_json({"user": user, "version": VERSION, "initial_pw": db.get_state(c, "initial_pw") == "set"})

    def password(self, user, _q):
        b = self.body()
        c = self.app.conn()
        if not db.check_password(c, user, s(b.get("old"), 256)):
            self.app.throttle(self.ip, fail=True)
            raise HttpError(400, "Current password is wrong")
        new = s(b.get("new"), 256)
        if len(new) < db.MIN_PASSWORD:
            raise HttpError(400, "Use at least %d characters" % db.MIN_PASSWORD)
        db.set_password(c, user, new)
        if db.get_state(c, "initial_pw") == "set":
            db.set_state(c, "initial_pw", "changed")
        c.commit()
        self.audit(user, "changed password")
        self.send_json({"ok": True})

    # --- data ---
    def daemon_state(self, c):
        try:
            st = json.loads(db.get_state(c, "daemon", "{}"))
        except ValueError:
            st = {}
        st["running"] = bool(st) and time.time() - st.get("heartbeat", 0) < 30
        return st

    def status(self, _user, _q):
        self.send_json(self.daemon_state(self.app.conn()))

    def summary(self, _user, _q):
        c, t = self.app.conn(), time.time()
        count = lambda sql, a=(): c.execute(sql, a).fetchone()[0]
        drives = db.rows(c, "SELECT a.serial, a.ts since, d.name, d.total size, m.mount, m.label, m.fs, m.total, "
                            "m.free, m.files, m.watched, b.ts blocked, p.kind list FROM attached a "
                            "JOIN devices d ON d.serial=a.serial LEFT JOIN mounts m ON m.serial=a.serial "
                            "LEFT JOIN blocked b ON b.serial=a.serial LEFT JOIN policy p ON p.serial=a.serial "
                            "WHERE d.storage=1 ORDER BY a.ts DESC, m.mount")
        self.send_json({
            "mode": db.get_setting(c, "mode"),
            "to_usb_24h": count("SELECT COUNT(*) FROM events WHERE epoch>? AND direction='to USB'", (t - 86400,)),
            "from_usb_24h": count("SELECT COUNT(*) FROM events WHERE epoch>? AND direction='from USB'", (t - 86400,)),
            "deleted_24h": count("SELECT COUNT(*) FROM events WHERE epoch>? AND action LIKE 'Deleted%'", (t - 86400,)),
            "drives": drives,
            "recent": self._events({"limit": "10", "category": "file"})["rows"],
            "daemon": self.daemon_state(c),
        })

    def devices(self, _user, _q):
        """Every USB drive seen so far (other USB devices are not shown)."""
        self.send_json(db.rows(self.app.conn(),
                               "SELECT d.*, p.kind list, b.ts blocked, "
                               "(SELECT COUNT(*) FROM attached a WHERE a.serial=d.serial) connected, "
                               "(SELECT GROUP_CONCAT(m.mount, '|') FROM mounts m WHERE m.serial=d.serial) mounts "
                               "FROM devices d LEFT JOIN policy p ON p.serial=d.serial "
                               "LEFT JOIN blocked b ON b.serial=d.serial WHERE d.storage=1 ORDER BY d.last DESC"))

    def _filter(self, q):
        where, args = ["1=1"], []
        if q.get("direction") == "both":
            where.append("e.direction<>''")
        for k in ("action", "category", "direction"):
            if q.get(k) and q[k] != "both":
                where.append("e.%s=?" % k)
                args.append(q[k])
        if q.get("serial"):
            where.append("e.serial=?")
            args.append(q["serial"].upper())
        if q.get("user"):
            where.append("(e.user=? OR e.login=?)")
            args += [q["user"]] * 2
        if q.get("q"):
            where.append("(e.path LIKE ? OR e.dest LIKE ? OR e.process LIKE ? OR e.cmdline LIKE ? OR e.serial LIKE ? "
                         "OR e.user LIKE ? OR e.login LIKE ? OR d.name LIKE ?)")
            args += ["%" + q["q"] + "%"] * 8
        for k, op in (("since", ">="), ("until", "<")):
            if q.get(k):
                try:
                    v = q[k]
                    t = float(v) if v.replace(".", "", 1).isdigit() else time.mktime(
                        dt.datetime.strptime(v[:10], "%Y-%m-%d").timetuple()) + (86400 if k == "until" else 0)
                except ValueError:
                    raise HttpError(400, "Bad %s date (use YYYY-MM-DD)" % k)
                where.append("e.epoch%s?" % op)
                args.append(t)
        if q.get("before"):
            where.append("e.id<?")
            args.append(int(q["before"]))
        return " AND ".join(where), args

    # The console shows USB drive activity only: every such event names the drive's serial. Service and
    # policy-change events have none (console changes are in the audit log instead), and events of USB
    # devices that are not drives (recorded by older versions) are left out too.
    EVENT_SQL = ("SELECT e.*, d.name device FROM events e LEFT JOIN devices d ON d.serial=e.serial "
                 "WHERE e.serial<>'' AND (d.serial IS NULL OR d.storage=1) AND ")

    def _events(self, q):
        w, args = self._filter(q)
        try:
            limit = max(1, min(int(q.get("limit") or 200), 1000))
        except ValueError:
            limit = 200
        rows = db.rows(self.app.conn(), self.EVENT_SQL + w + " ORDER BY e.id DESC LIMIT ?", args + [limit])
        return {"rows": rows, "more": len(rows) == limit}

    def events(self, _user, q):
        self.send_json(self._events(q))

    def events_csv(self, user, q):
        w, args = self._filter(q)
        rows = db.rows(self.app.conn(), self.EVENT_SQL + w + " ORDER BY e.id DESC LIMIT 500000", args)
        buf = io.StringIO()
        wr = csv.writer(buf)
        cols = ("ts", "category", "action", "direction", "device", "serial", "mount", "path", "dest", "size",
                "user", "login", "process", "pid", "cmdline", "sha256", "detail")
        wr.writerow(cols)
        for r in rows:
            wr.writerow(["" if r.get(k) is None else r.get(k) for k in cols])
        self.audit(user, "exported events", "%d rows" % len(rows))
        fname = "usbwatch-events-%s.csv" % dt.date.today()
        self.send_bytes(("\ufeff" + buf.getvalue()).encode("utf-8"), "text/csv; charset=utf-8",
                        {"Content-Disposition": "attachment; filename=%s" % quote(fname)})

    def deleted(self, _user, q):
        w, args = self._filter({"q": q.get("q", "")})
        sql = ("SELECT e.id, e.ts, e.serial, e.mount, e.path, e.size, e.action, e.user, e.login, e.process, "
               "d.name device, (SELECT v.id FROM vault v WHERE v.serial=e.serial AND "
               "lower(v.rel)=lower(ltrim(substr(e.path, length(e.mount)+1), '/')) ORDER BY v.id DESC LIMIT 1) vid "
               "FROM events e LEFT JOIN devices d ON d.serial=e.serial "
               "WHERE e.action IN ('Deleted','Deleted (offline)') AND " + w + " ORDER BY e.id DESC LIMIT 3000")
        self.send_json(db.rows(self.app.conn(), sql, args))

    def get_policy(self, _user, _q):
        self.send_json(db.rows(self.app.conn(), "SELECT p.*, d.name device, d.last, d.vid, d.pid, "
                                                "(SELECT COUNT(*) FROM attached a WHERE a.serial=p.serial) connected "
                                                "FROM policy p LEFT JOIN devices d ON d.serial=p.serial "
                                                "ORDER BY p.kind, p.name"))

    def set_policy(self, user, _q):
        b = self.body()
        kind = b.get("kind")
        if kind not in ("allow", "block", None):
            raise HttpError(400, "kind must be allow, block or null")
        serials = [s(x, 200).strip().upper() for x in b.get("serials") or [] if s(x).strip()]
        if not serials:
            raise HttpError(400, "No serials given")
        names = b.get("names") if isinstance(b.get("names"), dict) else {}
        c = self.app.conn()
        for sid in serials:
            if kind is None:
                c.execute("DELETE FROM policy WHERE serial=?", (sid,))
                continue
            name = s(names.get(sid) or b.get("name"), 255)
            if not name:
                r = c.execute("SELECT name FROM devices WHERE serial=? AND name<>''", (sid,)).fetchone()
                name = r[0] if r else ""
            c.execute("INSERT OR REPLACE INTO policy VALUES(?,?,?,?,?)", (sid, kind, name, s(b.get("note"), 500), time.time()))
        db.bump(c, "policy_rev")
        c.commit()
        self.audit(user, {"allow": "whitelisted", "block": "blacklisted", None: "removed from lists"}[kind],
                   ", ".join(serials)[:1500])
        self.send_json({"ok": True})

    def get_settings(self, _user, _q):
        c, cfg = self.app.conn(), self.app.cfg
        st = db.typed_settings(c)
        st.update({
            "version": VERSION, "conf_file": cfg.path, "data_dir": cfg.data_dir,
            "web": {"bind": cfg.bind_addresses(), "port": cfg.getint("web", "port"), "allow": cfg.getlist("web", "allow"),
                    "allowed_hosts": cfg.getlist("web", "allowed_hosts"), "tls": self.app.tls,
                    "session_hours": cfg.getint("web", "session_hours")},
            "events_file": cfg.get("logging", "events_file"), "syslog": cfg.getbool("logging", "syslog"),
            "vault": db.one(c, "SELECT COUNT(*) n, COALESCE(SUM(size),0) size FROM vault"),
            "users": db.rows(c, "SELECT name, created, changed, last_login FROM users ORDER BY name"),
        })
        self.send_json(st)

    def put_settings(self, user, _q):
        b, c, changes = self.body(), self.app.conn(), []
        for k, v in b.items():
            try:
                db.set_setting(c, k, v)
            except ValueError as e:
                raise HttpError(400, str(e))
            changes.append("%s=%s" % (k, s(v, 60)))
        c.commit()
        if changes:
            self.audit(user, "settings changed", ", ".join(changes))
        self.send_json({"ok": True})

    def audit_log(self, _user, _q):
        self.send_json(db.rows(self.app.conn(), "SELECT * FROM audit ORDER BY id DESC LIMIT 500"))

    def commands(self, _user, _q):
        self.send_json(db.rows(self.app.conn(), "SELECT * FROM commands ORDER BY id DESC LIMIT 50"))

    def add_command(self, user, _q):
        b = self.body()
        cmd = s(b.get("cmd"), 32)
        if cmd not in COMMANDS:
            raise HttpError(400, "Unknown command")
        a = b.get("args") if isinstance(b.get("args"), dict) else {}
        if cmd == "restore":
            args = {"vid": int(a.get("vid") or 0)}
        elif cmd == "rescan":
            args = {"mount": s(a.get("mount"), 4096)}
        elif cmd == "unmount":
            args = {"mount": s(a.get("mount"), 4096), "serial": s(a.get("serial"), 200).upper()}
        elif cmd == "force_block":
            args = {"serial": s(a.get("serial"), 200).upper()}
        else:
            args = {}
        c = self.app.conn()
        cur = c.execute("INSERT INTO commands(cmd,args,user,created) VALUES(?,?,?,?)",
                        (cmd, json.dumps(args), user, time.time()))
        c.commit()
        self.audit(user, "command " + cmd, json.dumps(args) if args else "")
        self.send_json({"ok": True, "id": cur.lastrowid})


def ssl_context(cfg):
    cert, key = cfg.get("web", "tls_cert"), cfg.get("web", "tls_key")
    if not cert:
        return None
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0) | getattr(ssl, "OP_NO_TLSv1_1", 0)
    ctx.load_cert_chain(cert, key or None)
    return ctx


def drop_privileges(user):
    import pwd
    import grp
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        sys.exit("user %r does not exist (create it, or pass --user root to keep root - not recommended)" % user)
    os.setgroups([g.gr_gid for g in grp.getgrall() if user in g.gr_mem] + [pw.pw_gid])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    os.environ["HOME"] = pw.pw_dir


def main(cfg, user="usbwatch"):
    os.umask(0o007)
    logging.basicConfig(level=getattr(logging, cfg.get("logging", "level").upper(), logging.INFO),
                        format="%(levelname)s %(message)s")
    if not cfg.getbool("web", "enabled"):
        log.info("web console disabled in %s", cfg.path)
        while True:
            time.sleep(3600)
    db.init(cfg.db_path).close()
    app = App(cfg)
    ctx = ssl_context(cfg)
    port = cfg.getint("web", "port")
    servers = []
    for addr in cfg.bind_addresses():
        try:
            servers.append(Server((addr, port), Handler, app, ctx))
        except OSError as e:
            sys.exit("cannot listen on %s port %d: %s" % (addr, port, e))
    if os.geteuid() == 0 and user != "root":           # sockets and TLS key are open: drop root now
        drop_privileges(user)
    def loopback(a):
        try:
            return ipaddress.ip_address(a).is_loopback
        except ValueError:
            return a == "localhost"
    non_local = [a for a in cfg.bind_addresses() if not loopback(a)]
    if non_local and not ctx:
        log.warning("console listens on %s without TLS; passwords cross the network in clear text", ", ".join(non_local))
    scheme = "https" if ctx else "http"
    for srv in servers:
        host = srv.server_address[0]
        log.info("USBWatch console %s on %s://%s:%d/", VERSION, scheme, "[%s]" % host if ":" in host else host, port)
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        servers[0].serve_forever()
    except KeyboardInterrupt:
        pass
    return 0

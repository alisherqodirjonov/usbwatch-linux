"""The monitoring daemon (runs as root).

  * every USB device plugged in / removed (serial, VID:PID, vendor, product, classes, port, speed)
  * USB filesystems mounted / unmounted (label, filesystem, UUID, capacity)
  * file activity on them: Created / Modified (written to USB), Read and Executed (from USB),
    Deleted, Renamed/Moved, Deleted (offline) - with the process and user responsible where the
    kernel can tell (fanotify)
  * whitelist / blacklist enforcement (sysfs 'authorized'), optional recovery vault and SHA-256 hashes
  * device history from the kernel log
The web console talks to it only through the database (settings, policy, commands tables).
"""
import os
import sys
import json
import time
import queue
import shutil
import fnmatch
import hashlib
import logging
import logging.handlers
import platform
import threading

from . import VERSION, db, sysusb
from . import kernel as K
from .watcher import TreeWatcher

log = logging.getLogger("usbwatch")

TO_USB, FROM_USB = "to USB", "from USB"


def vault_worker(jobs, done, vault_dir):
    """Copies files written to a USB drive into the local recovery vault and/or hashes them."""
    while True:
        eid, serial, path, rel, vmax, hmax = jobs.get()
        for _ in range(6):
            try:
                st = os.stat(path)
                if not os.path.isfile(path) or st.st_size == 0:
                    break
                do_vault = 0 < st.st_size <= vmax
                do_hash = 0 < st.st_size <= hmax
                if not (do_vault or do_hash):
                    break
                h, dest, out = hashlib.sha256(), None, None
                if do_vault:
                    dest = os.path.join(vault_dir, serial.replace("/", "_") or "unknown",
                                        "%d_%s" % (int(time.time() * 1000), os.path.basename(path)))
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    out = open(dest, "wb")
                try:
                    with open(path, "rb") as f:
                        for chunk in iter(lambda: f.read(1 << 20), b""):
                            h.update(chunk)
                            if out:
                                out.write(chunk)
                finally:
                    if out:
                        out.close()
                if dest:
                    shutil.copystat(path, dest)
                done.put((eid, serial, path, rel, dest, st.st_size, h.hexdigest()))
                break
            except PermissionError:
                time.sleep(1.5)                        # still being written / locked
            except Exception:
                break


class Daemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.db = db.init(cfg.db_path)
        self.q = queue.Queue()
        self.wake = threading.Event()
        self.stopping = threading.Event()
        self.attached, self.mounts, self.watchers = {}, {}, {}
        self.recent_block, self.block_lock = {}, threading.Lock()
        self.writers, self.read_seen, self.pending = {}, {}, []
        self.vault_jobs, self.vault_done, self.vault_pending = queue.Queue(), queue.Queue(), {}
        self.settings = db.typed_settings(self.db)
        self.policy = {"mode": "off", "allow": set(), "block": set()}
        self.policy_rev = None
        self.ignore = set()
        self.fan, self.fan_error, self.uevent = None, "", None
        self.skip = cfg.getlist("monitor", "skip_dirs")
        self.started = time.time()
        self.tick_n = 0
        self.next_history = 0
        self.next_housekeeping = 0
        self.history_running = threading.Event()
        self.events_file = cfg.get("logging", "events_file")
        self.syslog = None
        if cfg.getbool("logging", "syslog") and os.path.exists("/dev/log"):
            self.syslog = logging.getLogger("usbwatch.events")
            self.syslog.propagate = False
            h = logging.handlers.SysLogHandler(address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_AUTH)
            h.setFormatter(logging.Formatter("usbwatch[%d]: %%(message)s" % os.getpid()))
            self.syslog.addHandler(h)
            self.syslog.setLevel(logging.INFO)

    # --- events ---
    def event(self, category, action, **kw):
        t = time.time()
        e = {"ts": db.now_str(t), "epoch": t, "category": category, "action": action}
        e.update(kw)
        self.q.put(e)

    def mount_of(self, path):
        best = ""
        for m in self.mounts:
            if (path == m or path.startswith(m.rstrip("/") + "/")) and len(m) > len(best):
                best = m
        return best

    def file_emit(self, mount, serial):
        def emit(action, path, dest="", size=None, detail=""):
            direction = TO_USB if action in ("Created", "Modified") else ""
            cat = "file" if action not in ("Watch limit", "Event overflow") else "system"
            self.event(cat, action, mount=mount, serial=serial, path=path, dest=dest, size=size,
                       detail=detail, direction=direction)
        return emit

    def fan_loop(self):
        """fanotify thread: turn kernel access notifications into attribution records."""
        own, cache, recent = os.getpid(), {}, {}
        while not self.stopping.is_set():
            try:
                items = self.fan.read(1.0)
            except Exception as e:
                log.warning("fanotify read failed: %s", e)
                time.sleep(2)
                continue
            t = time.time()
            for kind, path, pid in items:
                if kind == "overflow":
                    self.event("system", "Event overflow", detail="fanotify queue overflowed; some reads not attributed")
                    continue
                if pid == own or not path:
                    continue
                key = (kind, path, pid)
                if kind == "write" and t - recent.get(key, 0) < 2:
                    continue                           # FAN_MODIFY storms during big copies
                recent[key] = t
                c = cache.get(pid)
                if not c or t - c[0] > 2:
                    c = cache[pid] = (t, K.procinfo(pid))
                self.q.put({"_kind": "access", "kind": kind, "path": path, "t": t, "proc": c[1]})
            if len(cache) > 2000:
                cache = {p: v for p, v in cache.items() if t - v[0] < 5}
            if len(recent) > 20000:
                recent = {k: v for k, v in recent.items() if t - v < 5}

    def ignored(self, proc):
        names = {proc.get("process", ""), os.path.basename(proc.get("exe", ""))}
        return any(n and (n in self.ignore or any(n == i[:15] for i in self.ignore)) for n in names)

    def on_access(self, a):
        path, proc, t = a["path"], a["proc"], a["t"]
        if a["kind"] == "write":
            self.writers[path] = (t, proc)
            return
        mount = self.mount_of(path)
        if not mount:
            return
        rel = os.path.relpath(path, mount)
        if any(fnmatch.fnmatch(part, pat) for part in rel.split(os.sep) for pat in self.skip):
            return
        if self.ignored(proc):
            return
        if a["kind"] == "exec":
            if not self.settings["log_exec"]:
                return
            action, direction = "Executed", FROM_USB
        else:
            if not self.settings["log_reads"]:
                return
            key = (path, proc.get("pid"))
            if t - self.read_seen.get(key, 0) < self.settings["read_dedup_s"]:
                return
            self.read_seen[key] = t
            action, direction = "Read", FROM_USB
        try:
            size = os.path.getsize(path)
        except OSError:
            size = None
        info = self.mounts.get(mount, {})
        e = {"ts": db.now_str(t), "epoch": t, "category": "file", "action": action, "direction": direction,
             "mount": mount, "serial": info.get("serial", ""), "path": path, "size": size}
        self._attr(e, proc)
        self.pending.append(e)

    @staticmethod
    def _attr(e, proc):
        for k in ("user", "login", "process", "pid", "cmdline"):
            e[k] = proc.get(k, "")

    def process_queue(self):
        snaps, t = [], time.time()
        while True:
            try:
                e = self.q.get_nowait()
            except queue.Empty:
                break
            kind = e.get("_kind")
            if kind == "snapshot":
                snaps.append(e)
            elif kind == "access":
                self.on_access(e)
            else:
                self.pending.append(e)
        for s in snaps:
            self.handle_snapshot(s["mount"], s["serial"], s["files"])
        # file events wait ~1.5 s so the fanotify record of who wrote the file can catch up
        ready = [e for e in self.pending if e["category"] != "file" or t - e["epoch"] >= 1.5]
        if not ready:
            return
        self.pending = [e for e in self.pending if not (e["category"] != "file" or t - e["epoch"] >= 1.5)]
        ready.sort(key=lambda e: e["epoch"])
        for e in ready:
            if e["action"] in ("Created", "Modified") and not e.get("process"):
                w = self.writers.get(e["path"])
                if w and t - w[0] < 120:
                    self._attr(e, w[1])
            e["id"] = db.insert_event(self.db, e)
        self.db.commit()
        self.track(ready)
        self.sink(ready)
        if len(self.writers) > 5000:
            self.writers = {p: v for p, v in self.writers.items() if t - v[0] < 120}
        if len(self.read_seen) > 20000:
            self.read_seen = {k: v for k, v in self.read_seen.items() if t - v < self.settings["read_dedup_s"]}

    def sink(self, evs):
        lines = [json.dumps({k: e.get(k) for k in db.EVENT_FIELDS + ("id",) if e.get(k) not in (None, "")},
                            ensure_ascii=False) for e in evs]
        if self.events_file:
            try:
                fd = os.open(self.events_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
            except OSError as e:
                log.warning("cannot write %s: %s", self.events_file, e)
                self.events_file = ""
        if self.syslog:
            for line in lines:
                self.syslog.info(line)

    # --- bookkeeping ---
    def track(self, evs):
        """Keep the per-drive file index current, remember devices and schedule vault copies / hashes."""
        c, vault_on, hmax = self.db, self.settings["vault_on"], self.settings["hash_max_mb"]
        for e in evs:
            a, serial, path, dest, mount = e["action"], e.get("serial", ""), e.get("path", ""), e.get("dest", ""), e.get("mount", "")
            if e["category"] != "file" or not serial or a in ("Read", "Executed", "Restored"):
                continue
            rel = os.path.relpath(path, mount) if mount and path.startswith(mount) else path
            if a in ("Created", "Modified"):
                c.execute("INSERT OR REPLACE INTO snapshot VALUES(?,?,?)", (serial, rel, e.get("size") or 0))
                if (vault_on or hmax) and e.get("detail") != "symlink":
                    self.vault_pending[(serial, path)] = (time.time() + 3, rel, e["id"])
            elif a == "Deleted":
                if e.get("detail", "").startswith("folder"):
                    c.execute("DELETE FROM snapshot WHERE serial=? AND (rel=? OR substr(rel,1,?)=?)",
                              (serial, rel, len(rel) + 1, rel + "/"))
                else:
                    c.execute("DELETE FROM snapshot WHERE serial=? AND rel=?", (serial, rel))
                self.vault_pending.pop((serial, path), None)
            elif a == "Renamed/Moved" and dest:
                nrel = os.path.relpath(dest, mount)
                if e.get("detail") == "folder":
                    moved = c.execute("SELECT rel,size FROM snapshot WHERE serial=? AND substr(rel,1,?)=?",
                                      (serial, len(rel) + 1, rel + "/")).fetchall()
                    c.execute("DELETE FROM snapshot WHERE serial=? AND substr(rel,1,?)=?", (serial, len(rel) + 1, rel + "/"))
                    c.executemany("INSERT OR REPLACE INTO snapshot VALUES(?,?,?)",
                                  [(serial, nrel + r[0][len(rel):], r[1]) for r in moved])
                    for vid, vrel in c.execute("SELECT id,rel FROM vault WHERE serial=? AND substr(rel,1,?)=?",
                                               (serial, len(rel) + 1, rel + "/")).fetchall():
                        c.execute("UPDATE vault SET rel=?, path=? WHERE id=?",
                                  (nrel + vrel[len(rel):], os.path.join(mount, nrel + vrel[len(rel):]), vid))
                else:
                    c.execute("DELETE FROM snapshot WHERE serial=? AND rel=?", (serial, rel))
                    c.execute("INSERT OR REPLACE INTO snapshot VALUES(?,?,?)", (serial, nrel, e.get("size") or 0))
                    c.execute("UPDATE vault SET path=?, rel=? WHERE serial=? AND lower(rel)=lower(?)",
                              (dest, nrel, serial, rel))
                    pend = self.vault_pending.pop((serial, path), None)
                    if pend:
                        self.vault_pending[(serial, dest)] = (time.time() + 3, nrel, pend[2])
        c.commit()

    def handle_snapshot(self, mount, serial, files):
        """Compare the drive's files with what we saw last time -> 'Deleted (offline)'."""
        c = self.db
        prior = dict(c.execute("SELECT rel,size FROM snapshot WHERE serial=?", (serial,)).fetchall())
        t = time.time()
        for rel, sz in prior.items():
            if rel not in files:
                db.insert_event(c, {"ts": db.now_str(t), "epoch": t, "category": "file", "action": "Deleted (offline)",
                                    "serial": serial, "mount": mount, "path": os.path.join(mount, rel), "size": sz,
                                    "detail": "missing since this drive was last seen here"})
        c.execute("DELETE FROM snapshot WHERE serial=?", (serial,))
        c.executemany("INSERT INTO snapshot VALUES(?,?,?)", [(serial, rel, sz) for rel, sz in files.items()])
        c.execute("UPDATE mounts SET files=? WHERE mount=?", (len(files), mount))
        c.commit()

    def vault_dispatch(self):
        t = time.time()
        vmax = self.settings["vault_max_mb"] * 1024 * 1024 if self.settings["vault_on"] else 0
        hmax = self.settings["hash_max_mb"] * 1024 * 1024
        for key, (due, rel, eid) in list(self.vault_pending.items()):
            if due <= t:
                del self.vault_pending[key]
                self.vault_jobs.put((eid, key[0], key[1], rel, vmax, hmax))

    def vault_collect(self):
        c, got = self.db, False
        while True:
            try:
                eid, serial, path, rel, vpath, size, sha = self.vault_done.get_nowait()
            except queue.Empty:
                break
            got = True
            c.execute("UPDATE events SET sha256=? WHERE id=?", (sha, eid))
            if not vpath:
                continue
            for vid, vp in c.execute("SELECT id,vpath FROM vault WHERE serial=? AND lower(rel)=lower(?)",
                                     (serial, rel)).fetchall():
                self._unlink_vault(vp)
                c.execute("DELETE FROM vault WHERE id=?", (vid,))
            c.execute("INSERT INTO vault(serial,rel,path,vpath,size,ts,sha256) VALUES(?,?,?,?,?,?,?)",
                      (serial, rel, path, vpath, size, db.now_str(), sha))
        if not got:
            return
        cap = self.settings["vault_cap_gb"] * 1024 ** 3
        total = c.execute("SELECT COALESCE(SUM(size),0) FROM vault").fetchone()[0]
        while total > cap:
            row = c.execute("SELECT id,vpath,size FROM vault ORDER BY id LIMIT 1").fetchone()
            if not row:
                break
            self._unlink_vault(row[1])
            c.execute("DELETE FROM vault WHERE id=?", (row[0],))
            total -= row[2] or 0
        c.commit()

    def _in_vault(self, p):
        v = os.path.realpath(self.cfg.vault_dir)
        return bool(p) and os.path.realpath(p).startswith(v + os.sep)

    def _unlink_vault(self, p):
        if self._in_vault(p):
            try:
                os.remove(p)
            except OSError:
                pass

    # --- policy ---
    def load_policy(self, force=False):
        rev = db.get_state(self.db, "policy_rev", "0")
        if rev == self.policy_rev and not force:
            return
        first = self.policy_rev is None
        self.policy_rev = rev
        self.settings = db.typed_settings(self.db)
        self.ignore = {x.strip() for x in self.settings["ignore_processes"].replace("\n", ",").split(",") if x.strip()}
        allow, block = set(), set()
        for serial, kind in self.db.execute("SELECT serial,kind FROM policy"):
            (allow if kind == "allow" else block).add(serial.upper())
        new = {"mode": self.settings["mode"], "allow": allow, "block": block}
        changed = new != self.policy
        self.policy = new
        if not changed and not first:
            return
        if not first:
            log.info("policy: mode=%s allow=%d block=%d", new["mode"], len(allow), len(block))
            self.event("policy", "Policy applied", detail="mode=%s whitelist=%d blacklist=%d" %
                       (new["mode"], len(allow), len(block)))
        self.enforce_all()

    def allowed(self, serial):
        p, s = self.policy, (serial or "").upper()
        if p["mode"] in ("blacklist", "whitelist") and s in p["block"]:
            return False
        if p["mode"] == "whitelist":
            return s in p["allow"]
        return True

    def must_block(self, dev):
        return sysusb.in_scope(dev) and not self.allowed(dev["serial"])

    def enforce_all(self):
        for h, dev in list(self.attached.items()):
            if dev.get("authorized", True) and self.must_block(dev):
                self.block(dev)
        for serial, handle in self.db.execute("SELECT serial,handle FROM blocked").fetchall():
            dev = self.attached.get(handle)
            if dev is None:
                self.db.execute("DELETE FROM blocked WHERE serial=?", (serial,))
            elif not self.must_block(dev):
                ok = sysusb.set_enabled(handle, True)
                self.event("policy", "Unblocked" if ok else "Unblock failed", serial=serial, path=handle,
                           detail=dev.get("name", ""))
                if ok:
                    dev["authorized"] = True
                    self.recent_block.pop(handle, None)
                    self.db.execute("DELETE FROM blocked WHERE serial=?", (serial,))
        self.db.commit()

    def block(self, dev, mount=""):
        h, serial = dev["handle"], dev["serial"]
        with self.block_lock:
            if time.time() - self.recent_block.get(h, 0) < 5:
                return True
            self.recent_block[h] = time.time()
        why = ""
        if sysusb.protected(h):
            why = "holds a system filesystem (/, /boot, ...); never blocked"
        elif not sysusb.blockable(h):
            why = "cannot identify this device in sysfs"
        elif not sysusb.is_root():
            why = "the daemon needs root rights"
        ok = not why and sysusb.set_enabled(h, False)
        if not ok and not why:
            why = "the kernel refused to deauthorize the device"
        self.event("policy", "Blocked" if ok else "Block failed", serial=serial, mount=mount, path=h,
                   detail=(dev.get("name", "") + " - " + ("mode " + self.policy["mode"] if ok else why)).strip(" -"))
        if ok:
            dev["authorized"] = False
            self.db.execute("INSERT OR REPLACE INTO blocked VALUES(?,?,?)", (serial, h, db.now_str()))
            self.db.commit()
        return ok

    # --- devices ---
    def upsert_device(self, d, connected=True):
        c, ts = self.db, db.now_str()
        cls = ",".join(d.get("classes", []))
        if not c.execute("SELECT 1 FROM devices WHERE serial=?", (d["serial"],)).fetchone():
            c.execute("INSERT INTO devices(serial,vid,pid,vendor,product,name,classes,storage,port,speed,first,last,"
                      "removed,times) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'',0)",
                      (d["serial"], d["vid"], d["pid"], d["vendor"], d["product"], d["name"], cls,
                       1 if d["storage"] else 0, d["port"], d.get("speed", ""), ts, ts))
        c.execute("UPDATE devices SET vid=?, pid=?, vendor=COALESCE(NULLIF(?,''),vendor), "
                  "product=COALESCE(NULLIF(?,''),product), name=COALESCE(NULLIF(?,''),name), "
                  "classes=COALESCE(NULLIF(?,''),classes), storage=MAX(storage,?), port=?, speed=?, last=?, "
                  "times=times+? WHERE serial=?",
                  (d["vid"], d["pid"], d["vendor"], d["product"], d["name"], cls, 1 if d["storage"] else 0,
                   d["port"], d.get("speed", ""), ts, 1 if connected else 0, d["serial"]))

    def on_attach(self, dev, startup=False):
        self.upsert_device(dev)
        self.db.execute("INSERT OR REPLACE INTO attached VALUES(?,?,?)", (dev["handle"], dev["serial"], db.now_str()))
        self.db.commit()
        if self.must_block(dev) and dev.get("authorized", True):
            self.block(dev)                            # first: deauthorize before anything mounts it
        self.event("device", "Connected", serial=dev["serial"], path=dev["handle"], dest=dev["name"],
                   detail="%s:%s  %s  port %s%s%s" % (dev["vid"], dev["pid"], sysusb.class_names(dev["classes"]),
                                                      dev["port"], ("  %s Mb/s" % dev["speed"]) if dev.get("speed") else "",
                                                      "  (already connected at start-up)" if startup else ""))

    def on_detach(self, dev, ts=None):
        self.db.execute("UPDATE devices SET removed=? WHERE serial=?", (ts or db.now_str(), dev["serial"]))
        self.db.execute("DELETE FROM attached WHERE handle=?", (dev["handle"],))
        self.db.execute("DELETE FROM blocked WHERE handle=?", (dev["handle"],))
        self.db.commit()
        self.recent_block.pop(dev["handle"], None)
        self.event("device", "Disconnected", serial=dev["serial"], path=dev["handle"], dest=dev.get("name", ""))

    def poll_devices(self, startup=False):
        cur = sysusb.usb_devices()
        t = time.time()
        if startup:
            known = dict(self.db.execute("SELECT handle,serial FROM attached").fetchall())
            drives = {r[0] for r in self.db.execute("SELECT serial FROM devices WHERE storage=1")}
            for h, serial in known.items():
                if h not in cur or cur[h]["serial"] != serial:
                    self.db.execute("DELETE FROM attached WHERE handle=?", (h,))
                    if serial not in drives:           # not a USB drive (recorded by an older version)
                        continue
                    self.db.execute("UPDATE devices SET removed=? WHERE serial=?", (db.now_str(), serial))
                    self.event("device", "Disconnected", serial=serial, path=h,
                               detail="removed while USBWatch was not running")
            self.db.commit()
        for h in [h for h in self.attached if h not in cur or cur[h]["serial"] != self.attached[h]["serial"]]:
            self.on_detach(self.attached.pop(h))
        for h, dev in cur.items():
            old = self.attached.get(h)
            if old is None:
                dev["_t"] = t
                self.attached[h] = dev
                if startup and h in known and known[h] == dev["serial"]:
                    self.upsert_device(dev, connected=False)
                    if self.must_block(dev) and dev["authorized"]:
                        self.block(dev)
                else:
                    self.on_attach(dev, startup)
            elif t - old.get("_t", 0) < 10 and old.get("authorized", True) and dev["classes"] != old["classes"]:
                dev["_t"] = old["_t"]                  # interfaces still appearing: classify again
                self.attached[h] = dev
                self.upsert_device(dev, connected=False)
                if self.must_block(dev):
                    self.block(dev)
        self.db.commit()

    # --- mounts ---
    def poll_mounts(self):
        cur = sysusb.mounted_roots()
        for m in [m for m in self.mounts if m not in cur]:
            info = self.mounts.pop(m)
            w = self.watchers.pop(m, None)
            if w:
                w.stop()
            if self.fan:
                try:
                    self.fan.mark(m, add=False)
                except Exception:
                    pass
            self.db.execute("DELETE FROM mounts WHERE mount=?", (m,))
            self.event("volume", "Unmounted", serial=info.get("serial", ""), mount=m, path=m, dest=info.get("label", ""))
        for m in cur:
            if m in self.mounts:
                continue
            info = sysusb.identify(m)
            if not info["usb"]:
                continue
            self.mounts[m] = info
            dev = self.attached.get(info["handle"]) or sysusb.describe(info["handle"])
            if self.must_block(dev) and dev.get("authorized", True) and self.block(dev, m):
                continue
            self.event("volume", "Mounted", serial=info["serial"], mount=m, path=m, dest=info["label"],
                       detail="%s  %s  UUID %s" % (info["fs"], info["source"], info["uuid"] or "-"))
            w = TreeWatcher(m, self.file_emit(m, info["serial"]),
                            lambda files, m=m, s=info["serial"]: self.q.put(
                                {"_kind": "snapshot", "mount": m, "serial": s, "files": files}),
                            skip=self.skip, max_watches=self.cfg.getint("monitor", "max_watches"))
            w.start()
            self.watchers[m] = w
            if self.fan:
                try:
                    self.fan.mark(m)
                except OSError as e:
                    log.warning("fanotify mark %s: %s", m, e)
            self.update_mount_row(m)
        self.db.commit()

    def update_mount_row(self, m):
        info = self.mounts.get(m)
        if not info:
            return
        try:
            total, _used, free = shutil.disk_usage(m)
        except OSError:
            total = free = None
        w = self.watchers.get(m)
        self.db.execute("INSERT OR REPLACE INTO mounts VALUES(?,?,?,?,?,?,?,?,?,"
                        "COALESCE((SELECT files FROM mounts WHERE mount=?),NULL),?)",
                        (m, info["serial"], info["label"], info["fs"], info["uuid"], info["source"], total, free,
                         0 if not w else (len(w.wds) if not w.limited else -len(w.wds)), m, time.time()))
        if total:
            self.db.execute("UPDATE devices SET total=?, label=?, fs=? WHERE serial=?",
                            (total, info["label"], info["fs"], info["serial"]))

    # --- commands ---
    def run_commands(self):
        for cid, cmd, args in self.db.execute("SELECT id,cmd,args FROM commands WHERE done IS NULL ORDER BY id").fetchall():
            try:
                a = json.loads(args or "{}")
                if cmd == "restore":
                    ok, msg = self.restore(int(a.get("vid", 0)))
                elif cmd == "refresh_history":
                    self.next_history = 0
                    ok, msg = True, "device history is being re-read from the kernel log"
                elif cmd == "rescan":
                    w = self.watchers.get(a.get("mount", ""))
                    if w:
                        w.rescan_requested.set()
                    ok, msg = (True, "re-indexing %s" % a.get("mount")) if w else (False, "not a watched USB mount")
                else:
                    ok, msg = False, "unknown command %r" % cmd
            except Exception as e:
                ok, msg = False, str(e)
            self.db.execute("UPDATE commands SET done=?, ok=?, result=? WHERE id=?", (time.time(), 1 if ok else 0, msg, cid))
            self.db.commit()

    def restore(self, vid):
        row = self.db.execute("SELECT serial,rel,vpath FROM vault WHERE id=?", (vid,)).fetchone()
        if not row or not self._in_vault(row[2]) or not os.path.isfile(row[2]):
            return False, "recovery copy not found"
        serial, rel, vpath = row
        root = next((m for m, i in self.mounts.items() if i["serial"].upper() == serial.upper()), None)
        if not root:
            return False, "the USB drive is not connected"
        dest = os.path.normpath(os.path.join(root, rel))
        if os.path.commonpath([os.path.realpath(root), os.path.realpath(os.path.dirname(dest))]) != os.path.realpath(root):
            return False, "refusing to restore outside the drive"
        base, ext = os.path.splitext(dest)
        n = 1
        while os.path.lexists(dest):
            dest = "%s (restored%s)%s" % (base, "" if n == 1 else " %d" % n, ext)
            n += 1
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(vpath, dest)
        self.event("file", "Restored", direction=TO_USB, serial=serial, mount=root, path=dest,
                   size=os.path.getsize(dest), detail="from recovery vault")
        return True, "restored to %s" % dest

    # --- history / housekeeping ---
    def history_thread(self):
        try:
            c = db.connect(self.cfg.db_path)
            devs = [d for d in sysusb.history() if d["storage"]]
            for d in devs:
                r = c.execute("SELECT first FROM devices WHERE serial=?", (d["serial"],)).fetchone()
                if not r:
                    c.execute("INSERT INTO devices(serial,vid,pid,vendor,product,name,classes,storage,port,speed,"
                              "first,last,removed,times) VALUES(?,?,?,?,?,?,?,?,?,'',?,?,?,?)",
                              (d["serial"], d["vid"], d["pid"], d["vendor"], d["product"], d["name"],
                               "08" if d["storage"] else "", 1 if d["storage"] else 0, d["port"], d["first"],
                               d["last"], d["removed"], d["times"]))
                else:
                    first = min([x for x in (r[0], d["first"]) if x] or [""])
                    c.execute("UPDATE devices SET first=?, vendor=COALESCE(NULLIF(vendor,''),?), "
                              "product=COALESCE(NULLIF(product,''),?), name=COALESCE(NULLIF(name,''),?), "
                              "storage=MAX(storage,?), times=MAX(times,?), "
                              "last=CASE WHEN COALESCE(last,'')<? THEN ? ELSE last END WHERE serial=?",
                              (first, d["vendor"], d["product"], d["name"], 1 if d["storage"] else 0, d["times"],
                               d["last"], d["last"], d["serial"]))
            db.set_state(c, "history", {"ts": time.time(), "devices": len(devs)})
            c.commit()
            c.close()
            log.info("device history: %d USB drives found in the kernel log", len(devs))
        except Exception:
            log.exception("history")
        finally:
            self.history_running.clear()

    def housekeeping(self):
        c, t = self.db, time.time()
        c.execute("DELETE FROM events WHERE epoch<?", (t - self.settings["retention_days"] * 86400,))
        c.execute("DELETE FROM sessions WHERE expires<?", (t,))
        c.execute("DELETE FROM audit WHERE ts<?", (t - 3 * 365 * 86400,))
        c.execute("DELETE FROM commands WHERE done IS NOT NULL AND done<?", (t - 30 * 86400,))
        c.commit()
        initial = os.path.join(os.path.dirname(self.cfg.path), "initial-admin-password")
        if db.get_state(c, "initial_pw") == "changed" and os.path.exists(initial):
            try:
                os.remove(initial)
            except OSError:
                pass

    def heartbeat(self):
        st = {
            "pid": os.getpid(), "version": VERSION, "started": self.started, "heartbeat": time.time(),
            "root": sysusb.is_root(), "kernel": platform.release(), "arch": platform.machine(),
            "python": platform.python_version(), "fanotify": "ok" if self.fan else (self.fan_error or "off"),
            "exec_events": bool(self.fan and self.fan.exec_ok),
            "netlink": "ok" if self.uevent and self.uevent.ok else (self.uevent.error if self.uevent else "off"),
            "watches": sum(len(w.wds) for w in self.watchers.values()), "inotify_limit": K.inotify_limit(),
            "pending": len(self.pending), "attached": len(self.attached), "mounts": len(self.mounts),
        }
        db.set_state(self.db, "daemon", st)
        self.db.commit()

    # --- main loop ---
    def tick(self):
        self.tick_n += 1
        t = time.time()
        self.load_policy()
        for fn in (self.poll_devices, self.poll_mounts):
            try:
                fn()
            except Exception:
                log.exception(fn.__name__)
        self.process_queue()
        self.run_commands()
        self.vault_dispatch()
        self.vault_collect()
        if self.tick_n % 5 == 1:
            for m in list(self.mounts):
                self.update_mount_row(m)
            self.heartbeat()
        if t >= self.next_history and not self.history_running.is_set():
            self.next_history = t + 3600
            self.history_running.set()
            threading.Thread(target=self.history_thread, name="history", daemon=True).start()
        if t >= self.next_housekeeping:
            self.next_housekeeping = t + 6 * 3600
            self.housekeeping()

    def run(self):
        os.makedirs(self.cfg.vault_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.cfg.vault_dir, 0o700)
        except OSError:
            pass
        self.db.execute("DELETE FROM mounts")
        self.db.commit()
        threading.Thread(target=vault_worker, args=(self.vault_jobs, self.vault_done, self.cfg.vault_dir),
                         name="vault", daemon=True).start()
        self.uevent = K.UeventListener(self.wake)
        self.uevent.start()
        if self.cfg.getbool("monitor", "process_attribution"):
            try:
                self.fan = K.Fanotify()
                threading.Thread(target=self.fan_loop, name="fanotify", daemon=True).start()
            except OSError as e:
                self.fan_error = str(e)
                log.warning("process attribution unavailable (%s); file events will not name the process", e)
        if not sysusb.is_root():
            log.warning("not running as root: devices cannot be blocked and reads cannot be attributed")
        self.load_policy(force=True)
        self.poll_devices(startup=True)
        self.event("system", "Service started", detail="USBWatch %s on %s %s (%s), Python %s" % (
            VERSION, platform.system(), platform.release(), platform.machine(), platform.python_version()))
        log.info("USBWatch %s started (root=%s, fanotify=%s)", VERSION, sysusb.is_root(), bool(self.fan))
        interval = max(0.2, self.cfg.getfloat("monitor", "poll_interval"))
        while not self.stopping.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("tick")
            self.wake.wait(interval)
            self.wake.clear()
        self.shutdown()

    def shutdown(self):
        for w in self.watchers.values():
            w.stop()
        self.event("system", "Service stopped")
        t = time.time()
        for e in self.pending:
            e["epoch"] = min(e["epoch"], t - 2)
        self.process_queue()
        self.heartbeat()
        self.db.close()


def setup_logging(cfg, foreground=True):
    level = getattr(logging, cfg.get("logging", "level").upper(), logging.INFO)
    log.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    try:
        os.makedirs(cfg.log_dir, exist_ok=True)
        h = logging.handlers.RotatingFileHandler(os.path.join(cfg.log_dir, "usbwatch.log"),
                                                 maxBytes=5000000, backupCount=5)
        h.setFormatter(fmt)
        log.addHandler(h)
    except OSError as e:
        print("log file unavailable: %s" % e, file=sys.stderr)
    if foreground and sys.stderr:
        s = logging.StreamHandler()
        s.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        log.addHandler(s)


def main(cfg):
    import signal
    os.umask(0o007)
    setup_logging(cfg)
    d = Daemon(cfg)

    def stop(*_a):
        d.stopping.set()
        d.wake.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    d.run()
    return 0

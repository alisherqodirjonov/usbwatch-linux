"""Recursive inotify watcher for one mounted USB filesystem.

Reports, per file:  Created (written to the drive and closed) - Modified - Deleted - Renamed/Moved,
plus folder renames/moves, and indexes the drive on start so the daemon can detect files deleted
while the drive was elsewhere.
"""
import os
import time
import fnmatch
import logging
import threading

from . import kernel as K

log = logging.getLogger("usbwatch")


class TreeWatcher(threading.Thread):
    def __init__(self, root, emit, on_index, skip=(), max_watches=200000):
        threading.Thread.__init__(self, name="watch:%s" % root, daemon=True)
        self.root, self.emit, self.on_index = root.rstrip("/") or "/", emit, on_index
        self.skip, self.max_watches = list(skip), max_watches
        self.stopping = threading.Event()
        self.rescan_requested = threading.Event()
        self.ino = None
        self.wds, self.created, self.moves, self.last_mod, self.scanned = {}, {}, {}, {}, {}
        self.files, self.limited, self.error = 0, False, ""

    # --- helpers ---
    def skipped(self, path):
        rel = os.path.relpath(path, self.root)
        return any(fnmatch.fnmatch(part, pat) for part in rel.split(os.sep) for pat in self.skip)

    def _watch(self, d):
        if len(self.wds) >= self.max_watches:
            self._limit("configured max_watches (%d) reached" % self.max_watches)
            return False
        try:
            wd = self.ino.add(d)
        except OSError as e:
            if e.errno == 28:                          # ENOSPC: fs.inotify.max_user_watches exhausted
                self._limit("fs.inotify.max_user_watches (%d) exhausted" % K.inotify_limit())
            return False
        self.wds[wd] = d
        return True

    def _limit(self, why):
        if not self.limited:
            self.limited = True
            self.emit("Watch limit", self.root, "", None, "Only part of this drive is watched: %s" % why)

    def _add_tree(self, top, index=None, announce=False):
        """Watch `top` and everything below it. index: dict to fill {rel: size}; announce: report files as Created."""
        for base, dirs, names in os.walk(top):
            if self.stopping.is_set():
                return
            dirs[:] = [x for x in dirs if not self.skipped(os.path.join(base, x))]
            self._watch(base)
            for n in names:
                fp = os.path.join(base, n)
                if self.skipped(fp):
                    continue
                try:
                    st = os.lstat(fp)
                except OSError:
                    continue
                if index is not None:
                    index[os.path.relpath(fp, self.root)] = st.st_size
                if announce:
                    self.scanned[fp] = time.time()
                    self.emit("Created", fp, "", st.st_size, "")

    def _drop_tree(self, top):
        for wd, p in list(self.wds.items()):
            if p == top or p.startswith(top + "/"):
                self.ino.rm(wd)
                self.wds.pop(wd, None)

    def _rename_tree(self, old, new):
        for wd, p in list(self.wds.items()):
            if p == old or p.startswith(old + "/"):
                self.wds[wd] = new + p[len(old):]

    @staticmethod
    def _size(p):
        try:
            return os.lstat(p).st_size
        except OSError:
            return None

    def index(self):
        files = {}
        self._add_tree(self.root, index=files)
        self.files = len(files)
        if not self.stopping.is_set():
            self.on_index(files)

    # --- event handling ---
    def handle(self, wd, mask, cookie, name):
        t = time.time()
        if mask & K.IN_Q_OVERFLOW:
            self.emit("Event overflow", self.root, "", None, "Kernel event queue overflowed; drive will be re-indexed")
            self.rescan_requested.set()
            return
        if mask & K.IN_UNMOUNT:
            self.stopping.set()
            return
        d = self.wds.get(wd)
        if d is None:
            return
        if mask & K.IN_IGNORED:
            self.wds.pop(wd, None)
            return
        if not name:                                   # event on the directory itself (DELETE_SELF)
            return
        path = os.path.join(d, name)
        isdir = bool(mask & K.IN_ISDIR)
        if self.skipped(path):
            return
        if mask & K.IN_CREATE:
            if isdir:
                self._add_tree(path, announce=True)    # mkdir -p / folder copied in: catch files racing the watch
            elif os.path.islink(path):
                try:
                    target = os.readlink(path)
                except OSError:
                    target = ""
                self.emit("Created", path, target, 0, "symlink")
            else:
                self.created[path] = t
                if len(self.created) > 50000:          # bound memory if something never closes its files
                    for p in sorted(self.created, key=self.created.get)[:10000]:
                        self.created.pop(p)
                        self.emit("Created", p, "", self._size(p), "")
        if mask & K.IN_CLOSE_WRITE:
            if self.created.pop(path, None) is not None:
                self.emit("Created", path, "", self._size(path), "")
            elif t - self.scanned.pop(path, 0) < 5:
                pass                                   # already reported by a folder scan
            elif t - self.last_mod.get(path, 0) >= 1.0:
                self.last_mod[path] = t
                self.emit("Modified", path, "", self._size(path), "")
        if mask & K.IN_DELETE and not isdir:
            self.created.pop(path, None)
            self.last_mod.pop(path, None)
            self.emit("Deleted", path, "", None, "")
        if mask & K.IN_MOVED_FROM:
            self.moves[cookie] = (t, path, isdir)
        if mask & K.IN_MOVED_TO:
            src = self.moves.pop(cookie, None)
            if src:
                if src[2]:
                    self._rename_tree(src[1], path)
                if self.created.pop(src[1], None) is not None:
                    self.created[path] = t             # renamed while still being written
                self.emit("Renamed/Moved", src[1], path, None if isdir else self._size(path),
                          "folder" if isdir else "")
            elif isdir:
                self._add_tree(path, announce=True)    # moved in from outside the drive's watched tree
            else:
                self.emit("Created", path, "", self._size(path), "moved in")

    def flush(self):
        t = time.time()
        for cookie, (ts, path, isdir) in list(self.moves.items()):
            if t - ts > 1.0:                           # MOVED_FROM with no MOVED_TO: moved out of the drive
                del self.moves[cookie]
                if isdir:
                    self._drop_tree(path)
                self.emit("Deleted", path, "", None, "folder moved out" if isdir else "moved out")
        if len(self.last_mod) > 20000:
            self.last_mod = {p: v for p, v in self.last_mod.items() if t - v < 5}
        if len(self.scanned) > 20000:
            self.scanned = {p: v for p, v in self.scanned.items() if t - v < 5}

    def run(self):
        try:
            self.ino = K.Inotify()
            self.index()
            while not self.stopping.is_set():
                if self.rescan_requested.is_set():
                    self.rescan_requested.clear()
                    self._drop_tree(self.root)
                    self.index()
                for ev in self.ino.read(0.5):
                    try:
                        self.handle(*ev)
                    except Exception:
                        log.exception("watch %s", self.root)
                self.flush()
        except Exception as e:
            self.error = str(e)
            log.exception("watcher for %s stopped", self.root)
        finally:
            for p in list(self.created):
                self.emit("Created", p, "", self._size(p), "")
            if self.ino:
                self.ino.close()

    def stop(self):
        self.stopping.set()

"""inotify tree watcher and daemon bookkeeping, exercised on a temp folder standing in for a USB drive."""
import os
import time
import shutil
import tempfile
import threading
import unittest

from helpers import temp_config

from usbwatch import db
from usbwatch.watcher import TreeWatcher
from usbwatch.daemon import Daemon


class WatcherTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="usbwatch-drive-")
        os.makedirs(os.path.join(self.root, "old"))
        with open(os.path.join(self.root, "old", "keep.txt"), "w") as f:
            f.write("x")
        os.makedirs(os.path.join(self.root, "lost+found"))
        self.events, self.index, self.lock = [], None, threading.Lock()
        self.indexed = threading.Event()

        def emit(action, path, dest="", size=None, detail=""):
            with self.lock:
                self.events.append((action, os.path.relpath(path, self.root), os.path.relpath(dest, self.root)
                                    if dest and dest.startswith(self.root) else dest, size, detail))

        def on_index(files):
            self.index = files
            self.indexed.set()
        self.w = TreeWatcher(self.root, emit, on_index, skip=["lost+found", ".Trash-*"])
        self.w.start()
        self.assertTrue(self.indexed.wait(5))

    def tearDown(self):
        self.w.stop()
        self.w.join(3)
        shutil.rmtree(self.root)

    def wait_for(self, pred, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                if pred(self.events):
                    return True
            time.sleep(0.05)
        return False

    def p(self, *a):
        return os.path.join(self.root, *a)

    def test_index(self):
        self.assertEqual(self.index, {os.path.join("old", "keep.txt"): 1})

    def test_file_lifecycle(self):
        with open(self.p("a.txt"), "w") as f:
            f.write("hello")
        self.assertTrue(self.wait_for(lambda ev: ("Created", "a.txt", "", 5, "") in ev))
        time.sleep(1.1)
        with open(self.p("a.txt"), "a") as f:
            f.write("!")
        self.assertTrue(self.wait_for(lambda ev: any(e[0] == "Modified" and e[1] == "a.txt" for e in ev)))
        os.rename(self.p("a.txt"), self.p("b.txt"))
        self.assertTrue(self.wait_for(lambda ev: any(e[:3] == ("Renamed/Moved", "a.txt", "b.txt") for e in ev)))
        os.remove(self.p("b.txt"))
        self.assertTrue(self.wait_for(lambda ev: any(e[:2] == ("Deleted", "b.txt") for e in ev)))

    def test_folders(self):
        src = tempfile.mkdtemp()
        os.makedirs(os.path.join(src, "pics", "2024"))
        with open(os.path.join(src, "pics", "2024", "p.jpg"), "wb") as f:
            f.write(b"\xff" * 10)
        shutil.copytree(os.path.join(src, "pics"), self.p("pics"))
        shutil.rmtree(src)
        self.assertTrue(self.wait_for(lambda ev: any(e[:2] == ("Created", os.path.join("pics", "2024", "p.jpg")) for e in ev)))
        os.rename(self.p("pics"), self.p("photos"))
        self.assertTrue(self.wait_for(lambda ev: any(e[0] == "Renamed/Moved" and e[4] == "folder" for e in ev)))
        with open(self.p("photos", "2024", "new.jpg"), "w") as f:     # watch followed the rename
            f.write("y")
        self.assertTrue(self.wait_for(lambda ev: any(e[:2] == ("Created", os.path.join("photos", "2024", "new.jpg")) for e in ev)))

    def test_moved_out_and_skip(self):
        outside = tempfile.mkdtemp()
        shutil.move(self.p("old", "keep.txt"), os.path.join(outside, "keep.txt"))
        self.assertTrue(self.wait_for(lambda ev: any(e[:2] == ("Deleted", os.path.join("old", "keep.txt")) for e in ev)))
        with open(self.p("lost+found", "ignored"), "w") as f:
            f.write("z")
        time.sleep(0.8)
        with self.lock:
            self.assertFalse(any("lost+found" in e[1] for e in self.events))
        shutil.rmtree(outside)


class DaemonBookkeepingTest(unittest.TestCase):
    def setUp(self):
        self.cfg, self.d = temp_config("[monitor]\nprocess_attribution = no\n")
        self.dm = Daemon(self.cfg)
        self.dm.load_policy(force=True)
        self.mount = os.path.join(self.d, "drive")
        os.makedirs(self.mount)
        self.dm.mounts[self.mount] = {"serial": "SER1", "handle": "", "label": "STICK", "fs": "vfat"}

    def tearDown(self):
        self.dm.db.close()
        shutil.rmtree(self.d)

    def flush(self):
        for e in self.dm.pending:
            e["epoch"] -= 5
        self.dm.process_queue()
        for e in self.dm.pending:
            e["epoch"] -= 5
        self.dm.process_queue()

    def rows(self, action):
        return db.rows(self.dm.db, "SELECT * FROM events WHERE action=? ORDER BY id", (action,))

    def test_offline_deletion_and_snapshot(self):
        emit = self.dm.file_emit(self.mount, "SER1")
        self.dm.handle_snapshot(self.mount, "SER1", {"a.txt": 3, os.path.join("d", "b.txt"): 4})
        emit("Created", os.path.join(self.mount, "c.txt"), "", 9, "")
        emit("Renamed/Moved", os.path.join(self.mount, "d"), os.path.join(self.mount, "e"), None, "folder")
        self.flush()
        snap = dict(self.dm.db.execute("SELECT rel,size FROM snapshot WHERE serial='SER1'").fetchall())
        self.assertEqual(snap, {"a.txt": 3, "c.txt": 9, os.path.join("e", "b.txt"): 4})
        self.dm.handle_snapshot(self.mount, "SER1", {"c.txt": 9})          # drive came back with files missing
        gone = sorted(os.path.relpath(r["path"], self.mount) for r in self.rows("Deleted (offline)"))
        self.assertEqual(gone, ["a.txt", os.path.join("e", "b.txt")])
        created = self.rows("Created")[0]
        self.assertEqual(created["direction"], "to USB")
        with open(self.cfg.get("logging", "events_file")) as f:
            self.assertIn('"action": "Created"', f.read())

    def test_attribution_and_reads(self):
        path = os.path.join(self.mount, "report.pdf")
        with open(path, "w") as f:
            f.write("data")
        proc = {"pid": 4242, "process": "cp", "exe": "/usr/bin/cp", "cmdline": "cp report.pdf /media/x",
                "user": "root", "login": "alice"}
        t = time.time()
        self.dm.q.put({"_kind": "access", "kind": "write", "path": path, "t": t, "proc": proc})
        self.dm.file_emit(self.mount, "SER1")("Created", path, "", 4, "")
        self.dm.q.put({"_kind": "access", "kind": "read", "path": path, "t": t, "proc": dict(proc, process="evince", pid=7)})
        self.dm.q.put({"_kind": "access", "kind": "read", "path": path, "t": t, "proc": dict(proc, process="evince", pid=7)})
        self.dm.q.put({"_kind": "access", "kind": "read", "path": path, "t": t,
                       "proc": dict(proc, process="tracker-miner-f", pid=8)})
        self.flush()
        c = self.rows("Created")[0]
        self.assertEqual((c["process"], c["login"], c["pid"]), ("cp", "alice", 4242))
        reads = self.rows("Read")
        self.assertEqual(len(reads), 1)                                    # de-duplicated, indexer ignored
        self.assertEqual((reads[0]["process"], reads[0]["direction"]), ("evince", "from USB"))

    def test_restore_refuses_traversal(self):
        vdir = os.path.join(self.cfg.vault_dir, "SER1")
        os.makedirs(vdir)
        vf = os.path.join(vdir, "1_x.txt")
        with open(vf, "w") as f:
            f.write("v")
        self.dm.db.execute("INSERT INTO vault(serial,rel,path,vpath,size,ts) VALUES('SER1','../../escape.txt','',?,1,'')", (vf,))
        self.dm.db.execute("INSERT INTO vault(serial,rel,path,vpath,size,ts) VALUES('SER1','x.txt','','/etc/passwd',1,'')")
        self.dm.db.execute("INSERT INTO vault(serial,rel,path,vpath,size,ts) VALUES('SER1','sub/x.txt','',?,1,'')", (vf,))
        self.assertFalse(self.dm.restore(1)[0])
        self.assertFalse(self.dm.restore(2)[0])
        ok, msg = self.dm.restore(3)
        self.assertTrue(ok, msg)
        self.assertTrue(os.path.exists(os.path.join(self.mount, "sub", "x.txt")))
        self.assertTrue(self.dm.restore(3)[0])
        self.assertTrue(os.path.exists(os.path.join(self.mount, "sub", "x (restored).txt")))

    def test_policy(self):
        self.dm.load_policy(force=True)
        self.assertTrue(self.dm.allowed("ANY"))
        db.set_setting(self.dm.db, "mode", "whitelist")
        self.dm.db.execute("INSERT INTO policy VALUES('GOOD','allow','','',0)")
        self.dm.db.commit()
        self.dm.load_policy()
        self.assertTrue(self.dm.allowed("good"))
        self.assertFalse(self.dm.allowed("OTHER"))
        mouse = {"serial": "M", "storage": False, "hid": True, "hub": False, "mtp": False}
        self.assertFalse(self.dm.must_block(mouse))


if __name__ == "__main__":
    unittest.main()

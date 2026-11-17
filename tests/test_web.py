"""Web console: network gate, auth, CSRF and the main API, against a real server on an ephemeral port."""
import json
import time
import shutil
import threading
import unittest
import http.client

from helpers import temp_config

from usbwatch import db, web


class WebTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg, cls.d = temp_config("[web]\nport = 0\nmax_failed_logins = 4\n")
        c = db.init(cls.cfg.db_path)
        db.set_password(c, "admin", "testpassword123")
        db.insert_event(c, {"ts": db.now_str(), "epoch": time.time(), "category": "file", "action": "Created",
                            "direction": "to USB", "serial": "ABC", "path": "/media/u/STICK/secret.docx", "size": 10,
                            "user": "alice", "process": "cp", "pid": 1})
        db.insert_event(c, {"ts": db.now_str(), "epoch": time.time(), "category": "file", "action": "Deleted",
                            "serial": "ABC", "mount": "/media/u/STICK", "path": "/media/u/STICK/old.txt"})
        # one USB drive and one mouse are plugged in; only the drive should be visible
        c.execute("INSERT INTO devices(serial,name,storage,last) VALUES('ABC','Stick',1,'2026-01-01 00:00:00')")
        c.execute("INSERT INTO devices(serial,name,storage,last) VALUES('MOUSE1','Mouse',0,'2026-01-01 00:00:00')")
        c.execute("INSERT INTO attached VALUES('/sys/devices/x/1-1','ABC','2026-01-01 00:00:00')")
        c.execute("INSERT INTO attached VALUES('/sys/devices/x/1-2','MOUSE1','2026-01-01 00:00:00')")
        db.insert_event(c, {"ts": db.now_str(), "epoch": time.time(), "category": "device", "action": "Connected",
                            "serial": "MOUSE1"})
        c.commit()
        c.close()
        cls.app = web.App(cls.cfg)
        cls.srv = web.Server(("127.0.0.1", 0), web.Handler, cls.app)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.d)

    def req(self, method, path, body=None, cookie="", host=None, csrf=True, origin=None):
        h = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or "127.0.0.1:%d" % self.port}
        if csrf:
            headers["X-Requested-With"] = "usbwatch"
        if cookie:
            headers["Cookie"] = cookie
        if origin:
            headers["Origin"] = origin
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        h.request(method, path, data, headers)
        r = h.getresponse()
        raw = r.read()
        h.close()
        try:
            payload = json.loads(raw.decode())
        except ValueError:
            payload = raw
        return r.status, payload, r.getheader("Set-Cookie") or "", r

    def login(self):
        st, _b, ck, _r = self.req("POST", "/api/login", {"user": "admin", "password": "testpassword123"})
        self.assertEqual(st, 200)
        self.assertIn("HttpOnly", ck)
        self.assertIn("SameSite=Strict", ck)
        return ck.split(";")[0]

    def test_static_and_headers(self):
        st, body, _c, r = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn(b"USBWatch", body)
        self.assertIn("frame-ancestors 'none'", r.getheader("Content-Security-Policy"))
        self.assertEqual(self.req("GET", "/static/../web.py")[0], 404)

    def test_requires_login(self):
        self.assertEqual(self.req("GET", "/api/summary")[0], 401)

    def test_dns_rebinding_host_refused(self):
        self.assertEqual(self.req("GET", "/", host="evil.example:80")[0], 421)

    def test_client_allow_list(self):
        self.assertTrue(self.app.client_allowed("127.0.0.1"))
        self.assertTrue(self.app.client_allowed("::ffff:127.0.0.1"))
        self.assertFalse(self.app.client_allowed("192.168.1.10"))

    def test_login_flow_and_api(self):
        ck = self.login()
        st, me, _c, _r = self.req("GET", "/api/me", cookie=ck)
        self.assertEqual((st, me["user"]), (200, "admin"))
        st, s, _c, _r = self.req("GET", "/api/summary", cookie=ck)
        self.assertEqual(st, 200)
        self.assertEqual(s["to_usb_24h"], 1)
        self.assertEqual([d["serial"] for d in s["drives"]], ["ABC"])
        st, devs, _c, _r = self.req("GET", "/api/devices", cookie=ck)
        self.assertEqual([d["serial"] for d in devs], ["ABC"])          # the mouse is not listed
        st, ev, _c, _r = self.req("GET", "/api/events?q=secret&direction=to%20USB", cookie=ck)
        self.assertEqual(len(ev["rows"]), 1)
        self.assertEqual(ev["rows"][0]["user"], "alice")
        st, ev, _c, _r = self.req("GET", "/api/events?direction=both", cookie=ck)
        self.assertEqual(len(ev["rows"]), 1)
        st, ev, _c, _r = self.req("GET", "/api/events?category=device", cookie=ck)
        self.assertEqual(ev["rows"], [])                                # mouse events are hidden
        st, csvb, _c, r = self.req("GET", "/api/events.csv", cookie=ck)
        self.assertEqual(st, 200)
        self.assertIn(b"secret.docx", csvb)
        self.assertEqual(len(self.req("GET", "/api/deleted", cookie=ck)[1]), 1)

    def test_csrf_and_policy(self):
        ck = self.login()
        body = {"serials": ["abc"], "kind": "block"}
        self.assertEqual(self.req("POST", "/api/policy", body, cookie=ck, csrf=False)[0], 403)
        self.assertEqual(self.req("POST", "/api/policy", body, cookie=ck, origin="http://evil.example")[0], 403)
        self.assertEqual(self.req("POST", "/api/policy", body, cookie=ck)[0], 200)
        pol = self.req("GET", "/api/policy", cookie=ck)[1]
        self.assertEqual([(p["serial"], p["kind"]) for p in pol], [("ABC", "block")])
        self.assertEqual(self.req("PUT", "/api/settings", {"mode": "evil"}, cookie=ck)[0], 400)
        self.assertEqual(self.req("PUT", "/api/settings", {"mode": "blacklist"}, cookie=ck)[0], 200)
        self.assertEqual(self.req("POST", "/api/commands", {"cmd": "rm -rf"}, cookie=ck)[0], 400)
        st, r, _c, _r = self.req("POST", "/api/commands", {"cmd": "restore", "args": {"vid": 3}}, cookie=ck)
        self.assertEqual(st, 200)
        audit = self.req("GET", "/api/audit", cookie=ck)[1]
        self.assertTrue(any(a["action"] == "blacklisted" for a in audit))

    def test_logout_invalidates(self):
        ck = self.login()
        self.assertEqual(self.req("POST", "/api/logout", {}, cookie=ck)[0], 200)
        self.assertEqual(self.req("GET", "/api/me", cookie=ck)[0], 401)

    def test_zz_lockout(self):
        for _ in range(4):
            self.req("POST", "/api/login", {"user": "admin", "password": "nope"})
        self.assertEqual(self.req("POST", "/api/login", {"user": "admin", "password": "testpassword123"})[0], 429)
        self.app.fails.clear()


if __name__ == "__main__":
    unittest.main()

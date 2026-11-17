import os
import time
import shutil
import tempfile
import unittest
import ipaddress
from unittest import mock

from helpers import temp_config

from usbwatch import db, sysusb


class ConfigTest(unittest.TestCase):
    def test_defaults_are_local_only(self):
        cfg, d = temp_config()
        self.assertEqual(cfg.bind_addresses(), ["127.0.0.1"])
        nets = cfg.allow_networks()
        self.assertTrue(any(ipaddress.ip_address("127.0.0.1") in n for n in nets if n.version == 4))
        self.assertFalse(any(ipaddress.ip_address("192.168.1.5") in n for n in nets if n.version == 4))
        self.assertIn("localhost", cfg.allowed_hosts())
        shutil.rmtree(d)

    def test_allow_list_and_hosts(self):
        cfg, d = temp_config("[web]\nbind = 0.0.0.0\nallow = 10.0.0.0/8, 192.168.1.7, bogus\nallowed_hosts = Box.Lan\n")
        nets = [n for n in cfg.allow_networks() if n.version == 4]
        self.assertTrue(any(ipaddress.ip_address("10.2.3.4") in n for n in nets))
        self.assertTrue(any(ipaddress.ip_address("192.168.1.7") in n for n in nets))
        self.assertIn("box.lan", cfg.allowed_hosts())
        self.assertNotIn("0.0.0.0", cfg.allowed_hosts())
        shutil.rmtree(d)


class DbTest(unittest.TestCase):
    def setUp(self):
        self.cfg, self.d = temp_config()
        self.c = db.init(self.cfg.db_path)

    def tearDown(self):
        self.c.close()
        shutil.rmtree(self.d)

    def test_settings_validation(self):
        db.set_setting(self.c, "mode", "whitelist")
        self.assertEqual(db.typed_settings(self.c)["mode"], "whitelist")
        for k, v in (("mode", "nope"), ("vault_max_mb", 0), ("retention_days", "x"), ("unknown", 1)):
            with self.assertRaises(ValueError):
                db.set_setting(self.c, k, v)
        db.set_setting(self.c, "vault_on", True)
        self.assertIs(db.typed_settings(self.c)["vault_on"], True)
        self.assertNotEqual(db.get_state(self.c, "policy_rev"), "")

    def test_passwords(self):
        db.set_password(self.c, "admin", "correct horse battery")
        self.assertTrue(db.check_password(self.c, "admin", "correct horse battery"))
        self.assertFalse(db.check_password(self.c, "admin", "wrong"))
        self.assertFalse(db.check_password(self.c, "ghost", "correct horse battery"))
        self.assertNotIn("correct", self.c.execute("SELECT hash FROM users").fetchone()[0])

    def test_insert_event(self):
        eid = db.insert_event(self.c, {"ts": db.now_str(), "epoch": time.time(), "category": "file",
                                       "action": "Created", "path": "/media/x/a.txt", "size": 5})
        self.assertEqual(db.one(self.c, "SELECT action FROM events WHERE id=?", (eid,))["action"], "Created")


class SysusbTest(unittest.TestCase):
    def test_timestamps(self):
        self.assertEqual(sysusb._ts("2024-03-01T10:00:00+0000 host kernel: x")[:7], "2024-03")
        self.assertEqual(sysusb._ts("2024-03-01T10:00:00,123456+02:00 h kernel: x")[:7], "2024-03")
        self.assertRegex(sysusb._ts("Mar  1 10:00:00 host kernel: x"), r"^\d{4}-03-01 10:00:00$")

    def test_history_parse(self):
        lines = [
            "2024-03-01T10:00:00+0000 h kernel: usb 1-2: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00",
            "2024-03-01T10:00:00+0000 h kernel: usb 1-2: Product: Cruzer Blade",
            "2024-03-01T10:00:00+0000 h kernel: usb 1-2: Manufacturer: SanDisk",
            "2024-03-01T10:00:00+0000 h kernel: usb 1-2: SerialNumber: 4c530001",
            "2024-03-01T10:00:01+0000 h kernel: usb-storage 1-2:1.0: USB Mass Storage device detected",
            "2024-03-01T10:05:00+0000 h kernel: usb 1-2: USB disconnect, device number 5",
            "2024-03-02T09:00:00+0000 h kernel: usb 1-3: New USB device found, idVendor=046d, idProduct=c077, bcdDevice=72.00",
            "2024-03-02T09:00:00+0000 h kernel: usb 1-3: Product: USB Optical Mouse",
        ]
        with mock.patch.object(sysusb, "_kernel_lines", return_value=lines):
            devs = {d["serial"]: d for d in sysusb.history()}
        self.assertTrue(devs["4C530001"]["storage"])
        self.assertEqual(devs["4C530001"]["name"], "SanDisk Cruzer Blade")
        self.assertTrue(devs["4C530001"]["removed"])
        self.assertIn("NOSERIAL-046D-C077", devs)
        self.assertFalse(devs["NOSERIAL-046D-C077"]["storage"])

    def test_descriptor_classes(self):
        d = tempfile.mkdtemp()
        dev = bytes([18, 1] + [0] * 16)                                # device descriptor
        cfg = bytes([9, 2, 32, 0, 1, 1, 0, 0x80, 50])                   # configuration
        intf = bytes([9, 4, 0, 0, 2, 0x08, 0x06, 0x50, 0])              # interface: mass storage
        ep = bytes([7, 5, 0x81, 2, 0, 2, 0])
        with open(os.path.join(d, "descriptors"), "wb") as f:
            f.write(dev + cfg + intf + ep + ep)
        self.assertEqual(sysusb._descriptor_classes(d), {"08"})
        shutil.rmtree(d)

    def test_scope(self):
        storage = {"storage": True, "hid": False, "hub": False, "mtp": False}
        mouse = {"storage": False, "hid": True, "hub": False, "mtp": False}
        phone = {"storage": False, "hid": False, "hub": False, "mtp": True}
        hub = {"storage": False, "hid": False, "hub": True, "mtp": False}
        self.assertTrue(sysusb.in_scope(storage, "storage"))
        self.assertFalse(sysusb.in_scope(mouse, "storage+mtp"))
        self.assertTrue(sysusb.in_scope(mouse, "all"))
        self.assertFalse(sysusb.in_scope(phone, "storage"))
        self.assertTrue(sysusb.in_scope(phone, "storage+mtp"))
        self.assertFalse(sysusb.in_scope(hub, "all"))

    def test_blockable_rejects_outside_sysfs(self):
        self.assertFalse(sysusb.blockable("/etc"))
        self.assertFalse(sysusb.set_enabled("/tmp/../etc", False))

    def test_live_enumeration_does_not_crash(self):
        self.assertIsInstance(sysusb.usb_devices(), dict)
        self.assertIsInstance(sysusb.mounted_roots(), dict)


if __name__ == "__main__":
    unittest.main()

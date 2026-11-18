"""USB devices, mounts and device control through sysfs / procfs, plus device history from the kernel log.

Everything here is plain file reads and writes, so it works the same on every architecture and
distribution with sysfs (kernel 2.6+). Blocking writes 0 to the device's sysfs 'authorized' file.
"""
import os
import re
import glob
import subprocess
import datetime as dt

SYS_USB = "/sys/bus/usb/devices"

USB_CLASSES = {
    "01": "Audio", "02": "Communications", "03": "HID", "05": "Physical", "06": "Imaging/MTP/PTP",
    "07": "Printer", "08": "Mass storage", "09": "Hub", "0a": "CDC data", "0b": "Smart card",
    "0d": "Content security", "0e": "Video", "0f": "Healthcare", "10": "Audio/Video", "11": "Billboard",
    "12": "USB-C bridge", "dc": "Diagnostic", "e0": "Wireless", "ef": "Miscellaneous",
    "fe": "Application specific", "ff": "Vendor specific",
}


def is_root():
    return os.geteuid() == 0


def _read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _usb_parent(syspath):
    """Walk up from a sysfs path to the USB device directory (the one that has idVendor)."""
    p = os.path.realpath(syspath)
    while p.startswith("/sys/devices/") and p != "/sys/devices":
        if os.path.exists(os.path.join(p, "idVendor")):
            return p
        p = os.path.dirname(p)
    return None


def serial_of(usbdir):
    """The device's identity: its USB serial number, or NOSERIAL-VID-PID when it has none."""
    s = _read(os.path.join(usbdir, "serial")).upper()
    if s:
        return s
    return ("NOSERIAL-%s-%s" % (_read(os.path.join(usbdir, "idVendor")),
                                _read(os.path.join(usbdir, "idProduct")))).upper()


def vidpid_key(vid, pid):
    """Policy key that matches every USB device with this vendor:product pair."""
    return ("VIDPID-%s-%s" % (vid or "", pid or "")).upper()


def _unescape(s):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def mounts():
    out = []
    try:
        with open("/proc/self/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    out.append((_unescape(parts[0]), _unescape(parts[1]), parts[2]))
    except OSError:
        pass
    return out


def usb_of_source(src):
    if not src.startswith("/dev/"):
        return None
    name = os.path.basename(os.path.realpath(src))
    p = "/sys/class/block/%s" % name
    return _usb_parent(p) if os.path.exists(p) else None


def system_usb():
    """USB devices that hold / or /boot (a system booted from USB) - never blocked or watched."""
    return {u for src, mnt, _ in mounts() if mnt in ("/", "/boot", "/boot/efi", "/usr", "/var", "/home")
            for u in [usb_of_source(src)] if u}


def mounted_roots():
    """{mount point: source device} for filesystems that live on a USB device."""
    sysusb = system_usb()
    roots = {}
    for src, mnt, _fs in mounts():
        u = usb_of_source(src)
        if u and u not in sysusb:
            roots[mnt] = src
    return roots


def _by(kind):
    out = {}
    for p in glob.glob("/dev/disk/by-%s/*" % kind):
        out[os.path.realpath(p)] = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)),
                                          os.path.basename(p))
    return out


def identify(root):
    """Describe the USB device behind a mount point."""
    for src, mnt, fs in reversed(mounts()):
        if mnt == root:
            u = usb_of_source(src)
            if not u:
                break
            real = os.path.realpath(src)
            return {"serial": serial_of(u), "handle": u, "label": _by("label").get(real, ""),
                    "uuid": _by("uuid").get(real, ""), "fs": fs, "source": src, "usb": True}
    return {"serial": "", "handle": "", "label": "", "uuid": "", "fs": "", "source": "", "usb": False}


def _interfaces(d):
    out = []
    for i in sorted(glob.glob(d + ":*")):
        if os.path.exists(i + "/bInterfaceClass"):
            out.append((_read(i + "/bInterfaceClass").lower(), _read(i + "/interface")))
    return out


def _descriptor_classes(real):
    """Interface classes from the raw descriptors. These exist as soon as the device is announced,
    before the kernel creates the interface directories, so a device can be classified (and blocked) at once."""
    try:
        with open(real + "/descriptors", "rb") as f:
            data = bytearray(f.read(65536))
    except OSError:
        return set()
    out, i = set(), 0
    while i + 2 <= len(data):
        ln, typ = data[i], data[i + 1]
        if ln < 2:
            break
        if typ == 4 and ln >= 9 and i + 5 < len(data):  # INTERFACE descriptor: bInterfaceClass at offset 5
            out.add("%02x" % data[i + 5])
        i += ln
    return out


def describe(real):
    """Attributes of one USB device directory in sysfs."""
    ifs = _interfaces(real)
    dclass = _read(real + "/bDeviceClass").lower()
    classes = sorted({c for c, _ in ifs} | _descriptor_classes(real) |
                     ({dclass} if dclass not in ("", "00", "ef") else set()))
    vendor, product = _read(real + "/manufacturer"), _read(real + "/product")
    vid, pid = _read(real + "/idVendor"), _read(real + "/idProduct")
    return {
        "handle": real, "serial": serial_of(real), "vid": vid, "pid": pid, "vendor": vendor, "product": product,
        "name": ("%s %s" % (vendor, product)).strip() or "USB device %s:%s" % (vid, pid),
        "classes": classes, "storage": "08" in classes, "port": os.path.basename(real),
        "speed": _read(real + "/speed"), "authorized": _read(real + "/authorized") != "0",
        "mtp": "06" in classes or any("mtp" in (s or "").lower() for _, s in ifs),
        "hid": "03" in classes, "hub": "09" in classes,
    }


def usb_devices(storage_only=True):
    """{sysfs path: description} for attached USB drives (mass storage).

    Laptops expose many internal parts over USB (webcam, Bluetooth, fingerprint reader, sometimes the
    keyboard), so everything else is skipped unless storage_only is False.
    """
    out = {}
    for d in glob.glob(SYS_USB + "/*"):
        b = os.path.basename(d)
        if ":" in b or b.startswith("usb"):
            continue
        real = os.path.realpath(d)
        if not os.path.exists(real + "/idVendor"):
            continue
        dev = describe(real)
        if storage_only and not dev["storage"]:
            continue
        out[real] = dev
    return out


def class_names(classes):
    return ", ".join(USB_CLASSES.get(c, "class " + c) for c in classes)


def in_scope(dev):
    """Does the access-control policy apply to this device? Only USB drives are ever blocked."""
    return bool(dev.get("storage")) and not dev.get("hub")


# --- blocking ---
def blockable(handle):
    return bool(handle) and handle.startswith("/sys/devices/") and \
        os.path.exists(os.path.join(handle, "authorized")) and not os.path.basename(handle).startswith("usb")


def protected(handle):
    return bool(handle) and any(u == handle or u.startswith(handle + "/") for u in system_usb())


def set_enabled(handle, enable):
    """Deauthorize / reauthorize a USB device (needs root). The kernel re-checks a device on replug."""
    handle = os.path.realpath(handle or "")
    if not blockable(handle):
        return False
    try:
        with open(os.path.join(handle, "authorized"), "w") as f:
            f.write("1" if enable else "0")
        return True
    except OSError:
        return False


def mountpoints_for_serial(serial):
    """Every currently-mounted path that belongs to the USB device with this serial."""
    if not serial:
        return []
    want = serial.upper()
    out = []
    for src, mnt, _fs in mounts():
        u = usb_of_source(src)
        if u and serial_of(u).upper() == want:
            out.append(mnt)
    return out


def ghost_mounts():
    """Mounts that still appear in /proc/self/mounts but whose source block device is gone.
    This happens after a lazy-unmount of a FUSE filesystem: the FUSE backend is dead but the
    mount record lingers. ls'ing such a mount returns EIO."""
    out = []
    for src, mnt, fs in mounts():
        if src.startswith("/dev/") and not os.path.exists(src):
            out.append((src, mnt, fs))
    return out


def force_unmount(mnt):
    """Lazy-unmount a filesystem so a blocked device can be torn off even while in use."""
    try:
        r = subprocess.run(["umount", "-l", mnt], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=15)
        return r.returncode == 0 or not os.path.ismount(mnt)
    except Exception:
        return False


def poweroff_port(handle):
    """Let the kernel power-manage the USB port down (best-effort; silent if unsupported)."""
    try:
        with open(os.path.join(handle or "", "power", "control"), "w") as f:
            f.write("auto")
        return True
    except OSError:
        return False


def _block_nodes_for_handle(handle):
    """Whole-disk sysfs entries (/sys/block/sdX) that live under this USB device."""
    real_handle = os.path.realpath(handle or "")
    if not real_handle:
        return []
    out = []
    for p in glob.glob("/sys/block/sd*"):
        u = _usb_parent(p)
        if u and os.path.realpath(u) == real_handle:
            out.append(p)
    return out


def scsi_delete(handle):
    """Tear block device entries out of the SCSI layer for every disk under this USB handle.

    On some kernels writing authorized=0 to the USB device does not cascade down to the block
    subsystem, so /dev/sdX stays visible and mountable. Writing 1 to the SCSI device's own
    `delete` file makes the block node actually disappear. Returns the names that were dropped.
    """
    done = []
    for p in _block_nodes_for_handle(handle):
        delete = os.path.join(p, "device", "delete")
        try:
            with open(delete, "w") as f:
                f.write("1")
            done.append(os.path.basename(p))
        except OSError:
            pass
    return done


# --- device history (kernel log) ---
_RX = re.compile(r"kernel:\s+(?:\[\s*[\d.]+\]\s+)?(usb|usb-storage|uas) (\d+-[\d.]+)(?::[\d.]+)?: (.*)$")


def _ts(line):
    tok = line.split(" ", 1)[0]
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:[.,]\d+)?([+-]\d\d:?\d\d|Z)?$", tok)
    if m:                                             # journalctl -o short-iso (fromisoformat needs 3.7)
        t = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
        tz = m.group(2)
        if tz:
            off = 0 if tz == "Z" else (int(tz[1:3]) * 60 + int(tz[-2:])) * (1 if tz[0] == "+" else -1)
            t = t - dt.timedelta(minutes=off)
            t = t.replace(tzinfo=dt.timezone.utc).astimezone().replace(tzinfo=None)
        return t.strftime("%Y-%m-%d %H:%M:%S")
    try:
        t = dt.datetime.strptime(line[:15], "%b %d %H:%M:%S").replace(year=dt.date.today().year)
        if t > dt.datetime.now():
            t = t.replace(year=t.year - 1)
        return t.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ""


def _kernel_lines():
    try:
        r = subprocess.run(["journalctl", "_TRANSPORT=kernel", "-o", "short-iso", "--no-pager", "-q"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=120)
        if r.returncode == 0 and r.stdout:
            return r.stdout.splitlines()
    except Exception:
        pass
    lines = []
    for p in sorted(glob.glob("/var/log/kern.log*") + glob.glob("/var/log/messages*") +
                    glob.glob("/var/log/syslog*"), reverse=True):
        if p.endswith((".gz", ".xz", ".bz2", ".zst")):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                lines.extend(f)
        except OSError:
            continue
    return lines


def history():
    """Every USB device the kernel log remembers (journald or kern.log / messages / syslog)."""
    sessions, cur = [], {}
    for line in _kernel_lines():
        m = _RX.search(line)
        if not m:
            continue
        kind, port, msg = m.groups()
        ts = _ts(line)
        if kind == "usb" and msg.startswith("New USB device found"):
            v = re.search(r"idVendor=(\w+), idProduct=(\w+)", msg)
            cur[port] = {"first": ts, "vid": v.group(1) if v else "", "pid": v.group(2) if v else "",
                         "product": "", "vendor": "", "serial": "", "storage": False, "removed": "", "port": port}
            sessions.append(cur[port])
        elif port in cur:
            s = cur[port]
            if kind in ("usb-storage", "uas"):
                s["storage"] = True
            elif msg.startswith("Product: "):
                s["product"] = msg[9:].strip()
            elif msg.startswith("Manufacturer: "):
                s["vendor"] = msg[14:].strip()
            elif msg.startswith("SerialNumber: "):
                s["serial"] = msg[14:].strip().upper()
            elif msg.startswith("USB disconnect"):
                s["removed"] = ts
                cur.pop(port)
    devs = {}
    for s in sessions:
        sid = s["serial"] or ("NOSERIAL-%s-%s" % (s["vid"], s["pid"])).upper()
        d = devs.setdefault(sid, {"serial": sid, "vid": s["vid"], "pid": s["pid"], "vendor": s["vendor"],
                                  "product": s["product"], "storage": False, "first": s["first"], "last": "",
                                  "removed": "", "times": 0, "port": s["port"]})
        d["storage"] = d["storage"] or s["storage"]
        d["vendor"], d["product"] = d["vendor"] or s["vendor"], d["product"] or s["product"]
        d["first"] = min([x for x in (d["first"], s["first"]) if x] or [""])
        d["last"] = max(d["last"], s["first"])
        d["removed"] = max(d["removed"], s["removed"])
        d["times"] += 1
    for d in devs.values():
        d["name"] = ("%s %s" % (d["vendor"], d["product"])).strip()
    return list(devs.values())


# --- misc ---
def logged_in_users():
    try:
        r = subprocess.run(["who"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=10)
        return sorted({l.split()[0] for l in r.stdout.splitlines() if l.strip()})
    except Exception:
        return []

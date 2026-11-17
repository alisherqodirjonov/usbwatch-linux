"""Thin ctypes bindings for inotify and fanotify, a netlink uevent listener and /proc process lookup.

Functions are resolved from the C library by name (glibc >= 2.13 or musl), never by raw syscall number,
and struct layouts are fixed-size with explicit native byte order, so this works on every Linux ISA
(x86_64, i386, aarch64, armhf, ppc64le, s390x, riscv64, ...).
"""
import os
import ctypes
import ctypes.util
import errno
import pwd
import socket
import struct
import threading
import time

_libc = None


def libc():
    global _libc
    if _libc is None:
        try:
            _libc = ctypes.CDLL(None, use_errno=True)
            _libc.inotify_init1                      # probe: some static Pythons hide libc symbols
        except (OSError, AttributeError):
            _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        _libc.inotify_init1.argtypes = [ctypes.c_int]
        _libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        _libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        if hasattr(_libc, "fanotify_init"):
            _libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
            _libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int,
                                            ctypes.c_char_p]
    return _libc


def _oserror(what):
    e = ctypes.get_errno()
    return OSError(e, "%s: %s" % (what, os.strerror(e)))


# --- inotify ---
IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO = 0x2, 0x8, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF = 0x100, 0x200, 0x400, 0x800
IN_UNMOUNT, IN_Q_OVERFLOW, IN_IGNORED = 0x2000, 0x4000, 0x8000
IN_ONLYDIR, IN_DONT_FOLLOW, IN_EXCL_UNLINK, IN_ISDIR = 0x01000000, 0x02000000, 0x04000000, 0x40000000
_IN_EVENT = struct.Struct("=iIII")                   # wd, mask, cookie, len (+ name)
WATCH_MASK = (IN_CREATE | IN_DELETE | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF |
              IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK)


class Inotify:
    def __init__(self):
        self.fd = libc().inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)   # IN_NONBLOCK == O_NONBLOCK on all ISAs
        if self.fd < 0:
            raise _oserror("inotify_init1")

    def add(self, path, mask=WATCH_MASK):
        wd = libc().inotify_add_watch(self.fd, os.fsencode(path), mask)
        if wd < 0:
            raise _oserror("inotify_add_watch")
        return wd

    def rm(self, wd):
        libc().inotify_rm_watch(self.fd, wd)

    def read(self, timeout):
        import select
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return []
        try:
            buf = os.read(self.fd, 256 * 1024)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EINTR):
                return []
            raise
        out, off = [], 0
        while off + _IN_EVENT.size <= len(buf):
            wd, mask, cookie, ln = _IN_EVENT.unpack_from(buf, off)
            name = buf[off + _IN_EVENT.size:off + _IN_EVENT.size + ln].split(b"\0", 1)[0]
            out.append((wd, mask, cookie, os.fsdecode(name)))
            off += _IN_EVENT.size + ln
        return out

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def inotify_limit():
    try:
        with open("/proc/sys/fs/inotify/max_user_watches") as f:
            return int(f.read())
    except (OSError, ValueError):
        return 0


# --- fanotify ---
FAN_CLASS_NOTIF, FAN_CLOEXEC, FAN_NONBLOCK, FAN_UNLIMITED_QUEUE = 0x0, 0x1, 0x2, 0x10
FAN_MARK_ADD, FAN_MARK_REMOVE, FAN_MARK_MOUNT = 0x1, 0x2, 0x10
FAN_MODIFY, FAN_CLOSE_WRITE, FAN_CLOSE_NOWRITE, FAN_OPEN_EXEC = 0x2, 0x8, 0x10, 0x1000
FAN_Q_OVERFLOW = 0x4000
FANOTIFY_METADATA_VERSION = 3
AT_FDCWD = -100
_FAN_META = struct.Struct("=IBBHQii")                # event_len, vers, reserved, metadata_len, mask, fd, pid


class Fanotify:
    """Mount-wide access notifications that carry the PID of the process that read or wrote the file.
    Needs CAP_SYS_ADMIN and CONFIG_FANOTIFY (on in every major distribution kernel since 2.6.37)."""

    def __init__(self):
        lc = libc()
        if not hasattr(lc, "fanotify_init"):
            raise OSError(errno.ENOSYS, "C library has no fanotify_init")
        flags = os.O_RDONLY | getattr(os, "O_LARGEFILE", 0) | os.O_CLOEXEC
        self.fd = lc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_QUEUE, flags)
        if self.fd < 0:
            raise _oserror("fanotify_init")
        self.exec_ok = True

    def mark(self, path, add=True):
        base = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE
        mask = base | (FAN_OPEN_EXEC if self.exec_ok else 0)
        flags = (FAN_MARK_ADD if add else FAN_MARK_REMOVE) | FAN_MARK_MOUNT
        r = libc().fanotify_mark(self.fd, flags, mask, AT_FDCWD, os.fsencode(path))
        if r < 0 and add and self.exec_ok and ctypes.get_errno() == errno.EINVAL:
            self.exec_ok = False                       # FAN_OPEN_EXEC needs kernel 5.0+
            r = libc().fanotify_mark(self.fd, flags, base, AT_FDCWD, os.fsencode(path))
        if r < 0 and add:
            raise _oserror("fanotify_mark")

    def read(self, timeout):
        """[(kind, path, pid)] where kind is 'write', 'read', 'exec' or 'overflow'."""
        import select
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return []
        try:
            buf = os.read(self.fd, 64 * 1024)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EINTR):
                return []
            raise
        out, off = [], 0
        while off + _FAN_META.size <= len(buf):
            ln, vers, _r, _ml, mask, fd, pid = _FAN_META.unpack_from(buf, off)
            if vers != FANOTIFY_METADATA_VERSION or ln < _FAN_META.size:
                break
            off += ln
            if fd < 0:
                if mask & FAN_Q_OVERFLOW:
                    out.append(("overflow", "", 0))
                continue
            try:
                path = os.readlink("/proc/self/fd/%d" % fd)
            except OSError:
                path = ""
            finally:
                os.close(fd)
            if path.endswith(" (deleted)"):
                path = path[:-10]
            if mask & FAN_OPEN_EXEC:
                out.append(("exec", path, pid))
            if mask & (FAN_MODIFY | FAN_CLOSE_WRITE):
                out.append(("write", path, pid))
            elif mask & FAN_CLOSE_NOWRITE:
                out.append(("read", path, pid))
        return out

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


# --- netlink uevents ---
NETLINK_KOBJECT_UEVENT = 15


class UeventListener(threading.Thread):
    """Wakes the daemon the moment the kernel announces a USB or block device, so a forbidden
    device is deauthorized within milliseconds, before the desktop gets a chance to mount it."""

    def __init__(self, wake):
        threading.Thread.__init__(self, name="uevent", daemon=True)
        self.wake, self.error, self.ok = wake, "", False

    def run(self):
        try:
            s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            s.bind((0, 1))
        except (OSError, AttributeError) as e:
            self.error = str(e)
            return
        self.ok = True
        while True:
            try:
                data = s.recv(65536)
            except OSError:
                time.sleep(1)
                continue
            for field in data.split(b"\0"):
                if field in (b"SUBSYSTEM=usb", b"SUBSYSTEM=block"):
                    self.wake.set()
                    break


# --- processes ---
_UNSET_LOGINUID = 4294967295
_users = {}


def username(uid):
    if uid is None:
        return ""
    if uid not in _users:
        try:
            _users[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _users[uid] = str(uid)
    return _users[uid]


def procinfo(pid):
    """Who is behind a PID: command, executable, command line, user and login user (survives sudo/su)."""
    base = "/proc/%d" % pid
    info = {"pid": pid, "process": "", "exe": "", "cmdline": "", "user": "", "login": ""}
    try:
        with open(base + "/comm") as f:
            info["process"] = f.read().strip()
        with open(base + "/cmdline", "rb") as f:
            info["cmdline"] = f.read(2048).replace(b"\0", b" ").strip().decode("utf-8", "replace")[:1000]
        uid = None
        with open(base + "/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    break
        info["user"] = username(uid)
        try:
            with open(base + "/loginuid") as f:
                luid = int(f.read().strip())
            if luid != _UNSET_LOGINUID and luid != uid:
                info["login"] = username(luid)
        except (OSError, ValueError):
            pass
        try:
            info["exe"] = os.readlink(base + "/exe")
        except OSError:
            pass
    except (OSError, ValueError):
        if not info["process"]:
            info["process"] = "(exited)"
    return info

# Architecture

```
            kernel                                    usbwatch daemon (root)                      usbwatch web (user usbwatch)
 ┌──────────────────────────┐        ┌─────────────────────────────────────────────┐        ┌──────────────────────────────┐
 │ netlink uevent (usb/blk) ├─wake──►│ main loop (1 s, or immediately on uevent)   │        │ HTTP(S) on 127.0.0.1:8790    │
 │ sysfs /sys/bus/usb       ├─poll──►│  devices: connect/disconnect, policy, block ├─write─►│ IP allow-list → Host check → │
 │ /proc/self/mounts        ├─poll──►│  mounts: start/stop watchers, fanotify mark │  SQLite│ session → CSRF → JSON API    │
 │ inotify (per drive tree) ├─thread►│  events: attribute → DB + JSONL + syslog    │◄─read──┤ settings / policy / commands │
 │ fanotify (per mount)     ├─thread►│  vault + SHA-256 worker, restore, history   │        │ static single-page console   │
 │ journald / kern.log      ├─hourly►│  housekeeping (retention)                   │        └──────────────────────────────┘
 └──────────────────────────┘        └─────────────────────────────────────────────┘
```

## Modules

| File | Role |
|---|---|
| `usbwatch/sysusb.py` | sysfs/procfs: USB device enumeration (incl. raw-descriptor class parsing), mounts → USB parent, block/unblock via `authorized`, kernel-log history (ported from the agent's `backend_linux.py`) |
| `usbwatch/kernel.py` | ctypes inotify + fanotify, netlink uevent listener, `/proc/<pid>` lookup (user, login user, comm, exe, cmdline) |
| `usbwatch/watcher.py` | recursive inotify tree watcher for one drive: index, Created/Modified/Deleted/Renamed (files and folders), move in/out, overflow re-index |
| `usbwatch/daemon.py` | the service: policy, device/mount tracking, event pipeline, snapshots (offline deletions), vault/hash, commands, history, heartbeat |
| `usbwatch/web.py` | stdlib HTTP server: network gate, auth, API, CSV export, privilege drop |
| `usbwatch/db.py` | schema, settings validation, passwords, audit |
| `usbwatch/config.py` | root-owned INI file |
| `usbwatch/cli.py` | `usbwatch` command (daemon, web, setup, status, doctor, passwd, events, devices, unblock-all, open) |
| `usbwatch/static/` | console UI (vanilla JS, no external resources, light/dark) |

## How a transfer is attributed

1. inotify (one thread per drive) sees `IN_CREATE` and then `IN_CLOSE_WRITE` for `/media/alice/STICK/report.pdf`.
   The watcher emits **Created** with the final size.
2. fanotify, through a mount mark, sees `FAN_MODIFY`/`FAN_CLOSE_WRITE` on the same file and gets the PID of
   the writer. The fanotify thread reads `/proc/PID` straight away, while the process is still alive, and
   records the writer.
3. The main loop holds file events for about 1.5 s, attaches the writer record to the Created event, writes
   it to SQLite, JSONL and syslog, and updates the drive index. When hashing or the vault is on, it queues
   the file for that.
4. A `FAN_CLOSE_NOWRITE` from another process, for example `cp` copying the file *off* the drive, becomes a
   **Read** event with direction "from USB". It is skipped if the process is on the ignore list, or if the
   same process read the same file within the de-duplication window. `FAN_OPEN_EXEC` becomes **Executed**.

## How blocking works

The kernel announces a new USB device over netlink, which wakes the main loop immediately. The interface
classes come from the device's raw `descriptors` file, which exists before the interfaces are bound. If
policy says no, the daemon writes `0` to `/sys/devices/.../authorized` before any driver claims the device.
A deauthorized device stays in sysfs until it is unplugged. On replug it is announced again and blocked
again. A device that holds `/`, `/boot`, `/usr`, `/var` or `/home` is never blocked. When the policy changes,
devices that are now allowed are re-authorized.

## Privilege separation

Only the daemon is root. The console process runs as `usbwatch`. Under systemd it also gets
`ProtectSystem=strict`, an empty capability set, `PrivateDevices`, a syscall filter and more. Its only
writable path is the database folder. The console never touches devices or files. It writes rows
(settings, policy, `commands`), and the daemon validates and executes them. Restores, for example, are
confined to the vault folder and the drive's own mount point. Even a compromised console cannot get root
to write outside those places.

## Limitations

- Deletes and renames are not attributed to a process. Attributing them needs fanotify directory events,
  which require kernel 5.1+ with FID reporting and are not implemented. Events from the same moment usually make the author clear.
- Reads are file opens without writes. Previews and antivirus scans also count. Use the ignore list.
- Huge drives can exceed `fs.inotify.max_user_watches`. The console then shows **Watch limit**. Raise the
  limit with `sysctl fs.inotify.max_user_watches=524288`, and make it persistent in `/etc/sysctl.d/`.
- MTP phones are not mounted as filesystems, so the device is logged and can be blocked, but file transfers
  through gvfs/MTP are not visible at the file level.
- Anyone with root can stop the service or edit the database. Forward `events.jsonl` or syslog to a remote
  collector if you need tamper-evidence.

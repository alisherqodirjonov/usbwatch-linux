# Compatibility and minimum requirements

The minimums were chosen so that every enterprise and desktop distribution still in support runs USBWatch
with **no extra packages** beyond `python3`. Run `sudo usbwatch doctor` to check a machine. The installer
runs the same checks and refuses kernels older than 3.10 unless you pass `--force`.

## Hard requirements

| Component | Minimum | Why this version |
|---|---|---|
| Linux kernel | **3.10** | inotify (2.6.13), netlink uevents, sysfs `authorized` (2.6.x) and fanotify (2.6.37) are all present. 3.10 is the oldest kernel in a still-supported enterprise distribution. |
| Python | **3.6**, standard library only | 3.6 is the system Python of RHEL/Alma/Rocky 8, openSUSE Leap 15 and Ubuntu 18.04. The code avoids 3.7+ APIs (no `capture_output`, `fromisoformat`, `ThreadingHTTPServer`, dataclasses or walrus). |
| SQLite | 3.7 (WAL) | The SQL avoids UPSERT and window functions, so the SQLite 3.22 in Ubuntu 18.04 is fine. |
| C library | glibc ≥ 2.13 or musl | `inotify_init1`, `fanotify_init` and `fanotify_mark` are looked up by name through ctypes. |
| Privileges | root for the daemon | Blocking writes to sysfs, and fanotify needs `CAP_SYS_ADMIN`. The console runs unprivileged. |

## Instruction set architectures (ISA)

USBWatch is pure Python, and the kernel interfaces are reached **through libc symbols, never raw syscall
numbers**. The structs it parses (`inotify_event`, 16 bytes; `fanotify_event_metadata`, 24 bytes) have the
same layout on every architecture and are decoded in native byte order. Packages are therefore
`Architecture: all` / `noarch`.

| ISA | Status |
|---|---|
| x86_64 / amd64 | tested (Ubuntu 24.04, kernel 7.0) |
| i386 / i686, aarch64 / arm64, armhf / armv7, ppc64le, s390x (big endian), riscv64, loongarch64, mips64el | supported by design: no ISA-specific code |

## Distributions

| Family | Minimum release | Python | Init | Install with |
|---|---|---|---|---|
| Ubuntu | 18.04 LTS | 3.6 | systemd | `.deb`, `.run`, `make install` |
| Debian | 10 (buster) | 3.7 | systemd / sysvinit | `.deb`, `.run`, `make install` |
| Linux Mint / Pop!_OS / elementary / Zorin / Kali | releases based on Ubuntu 18.04 / Debian 10 or later | ≥ 3.6 | systemd | `.deb` |
| Devuan | 3 (beowulf) | 3.7 | sysvinit / OpenRC | `.run`, `make install` |
| RHEL / AlmaLinux / Rocky / Oracle Linux / CentOS Stream | 8 | 3.6 | systemd | `.rpm`, `.run` |
| Fedora | 30 | ≥ 3.7 | systemd | `.rpm`, `.run` |
| openSUSE Leap / SLES | 15 | 3.6 | systemd | `.rpm`, `.run` |
| Arch / Manjaro / EndeavourOS | rolling | current | systemd | `.run`, `make install` |
| Alpine | 3.12 | ≥ 3.8 (`apk add python3`) | OpenRC | `.run`, `make install` |
| Gentoo / Artix | current | current | OpenRC / systemd | `make install` |
| Slackware | 15.0 | 3.9 | SysV (BSD-style rc) | `make install INIT=sysvinit` |

## Feature support by kernel / environment

Every optional feature degrades gracefully. The console shows what is active, and so does `usbwatch status`.

| Feature | Needs | Without it |
|---|---|---|
| Device connect/disconnect log, mounts, file create/modify/delete/rename | kernel 3.10, sysfs, inotify | — (core) |
| Instant (pre-mount) blocking | netlink `NETLINK_KOBJECT_UEVENT` | 1-second polling (still before most automounters) |
| Blocking at all | root, writable sysfs | logged as "Block failed" with the reason |
| User/process attribution for writes; **Read** events (files copied *from* USB) | fanotify (`CONFIG_FANOTIFY=y`, on in all major distro kernels), root | file events have no user/process; reads are not logged |
| **Executed** events | kernel ≥ 5.0 (`FAN_OPEN_EXEC`) | executions show up as Read |
| Device history before installation | journald, `/var/log/kern.log`, `/var/log/messages` or `/var/log/syslog` | history starts at installation |
| Autostart | systemd, OpenRC, SysV init (LSB / chkconfig / rc.d) | `--init none`: start the two commands yourself |
| Desktop launcher | freedesktop `.desktop` support | use `usbwatch open` or a browser |

## Containers and VMs

In containers, `/sys/bus/usb` and netlink are usually absent, and the doctor warns about it. VMs with USB
pass-through behave like bare metal. Development was done on VMware, where the virtual hub and mouse are
logged as devices.

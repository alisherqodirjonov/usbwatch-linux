# USBWatch for Linux

A standalone USB auditing tool for Linux. It logs every USB device plugged in and everything done with
USB drives: files written to them, read or copied from them, deleted, renamed or executed, together with
the **user and process** responsible. It can whitelist or blacklist devices. It has a password-protected
web console that, by default, is reachable from this computer only.

It was extracted from the USBWatch managed edition (server + Windows/Linux agents) and needs no server.

> Use only on computers you own or are authorized to monitor, and tell the people who use them.

## Quick start

```bash
sudo make install                 # or: sudo ./scripts/install.sh
usbwatch open                     # opens http://127.0.0.1:8790/  - sign in as 'admin'
```

The installer asks for the console password. When there is no terminal, it generates one, prints it
once and saves it to `/etc/usbwatch/initial-admin-password` (readable by root only).

Other ways to install:

| Target | Command | Result |
|---|---|---|
| Any distribution, one file | `make run-installer`, then `sudo sh dist/usbwatch-1.0.0.run` | self-extracting installer |
| Debian / Ubuntu / Mint | `make deb`, then `sudo apt install ./dist/usbwatch_1.0.0_all.deb` | `.deb` (arch `all`) |
| RHEL / Rocky / Alma / Fedora / openSUSE | `make rpm`, then `sudo dnf install dist/usbwatch-1.0.0-1*.noarch.rpm` | `.rpm` (noarch) |
| Source tarball | `make dist` | `dist/usbwatch-linux-1.0.0.tar.gz` |

To remove it, run `sudo make uninstall`, which keeps the config, data and logs. `sudo make purge` removes
everything. Any device the tool blocked is re-enabled first.

## What is logged

| Category | Events | Details recorded |
|---|---|---|
| Devices | Connected, Disconnected | unique ID (USB serial, or `NOSERIAL-VID-PID`), VID:PID, vendor, product, USB classes, port, speed, first/last seen, times connected |
| Mounts | Mounted, Unmounted | mount point, label, filesystem, UUID, block device, capacity / free space, file count |
| Files **to** USB | Created, Modified, Restored | path, size, user, login user (survives `sudo`), process, PID, command line, optional SHA-256 |
| Files **from** USB | Read (opened / copied off the drive), Executed | path, size, user, process, PID, command line |
| Other file events | Deleted, Renamed/Moved (files and folders), Deleted (offline) | path, new path, size |
| Policy | Blocked, Block failed, Unblocked, Policy applied | device, reason |
| Service | Service started/stopped, Watch limit, Event overflow | kernel/arch/Python, cause |
| Console | Audit log: sign-ins (including failures), every setting/policy change, exports, commands | user, client IP |

"Deleted (offline)" means a file that disappeared while the drive was plugged in somewhere else. The tool
indexes every drive, so it can tell when the drive comes back.

Events are stored in SQLite (`/var/lib/usbwatch/usbwatch.db`). Each event is also appended as one JSON line
to `/var/log/usbwatch/events.jsonl` for SIEM or log shippers, and can be sent to syslog as well. You can
browse and export events from the console (filters, CSV export) or from the command line:

```bash
usbwatch events -n 100            # latest events     (-f to follow, --json / --csv to export)
usbwatch devices                  # every USB device ever seen, including kernel-log history
usbwatch status                   # service health, policy, mounted drives
sudo usbwatch doctor              # check this machine against the requirements
```

## Access control

You set this up on the console's **Access Control** page:

- **Off** logs only.
- **Blacklist** blocks the listed devices.
- **Whitelist only** blocks every device in scope that is not on the whitelist.

The scope can be USB mass storage, mass storage plus phones and cameras (MTP/PTP), or all USB devices.
Keyboards and mice are blocked only when the scope is "all". Blocking deauthorizes the device in the
kernel through sysfs. The kernel's netlink uevent wakes the service the moment a device appears, so
blocking happens within milliseconds, before the desktop mounts the drive.

**Emergency:** `sudo usbwatch unblock-all` sets the policy to Off and re-enables every blocked device.

## Console security

- The console listens on `127.0.0.1:8790`. Only the root-owned `/etc/usbwatch/usbwatch.conf` can change
  the bind address, the client allow-list (IP addresses and CIDRs) or the TLS settings. The console cannot
  widen its own exposure. Connections from clients that are not allowed are dropped before any HTTP is read.
- The `Host` header is checked to stop DNS rebinding. State-changing requests must carry a custom header,
  and their Origin is checked (CSRF protection). The CSP is strict and has no inline script.
- Passwords are hashed with PBKDF2-SHA256 (200k rounds). Session tokens are random and stored hashed, in an
  HttpOnly + SameSite=Strict cookie (also Secure under TLS). Sign-in locks out after 10 failures in
  10 minutes. Sessions expire after 8 h idle.
- The console runs as the unprivileged `usbwatch` user, under a sandboxed systemd unit. Only the monitoring
  daemon runs as root, and the two talk only through the database.

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) to allow remote access.

## Documentation

- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md): supported distributions, kernel, Python and ISAs, and which features need what.
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md): config file, remote/TLS access, users, files and paths.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how it works, data model, limitations.

## Development

```bash
make test        # 27 unit/integration tests, no root needed
make lint        # byte-compile + sh -n on every shell script
make run-dev     # daemon + console from the source tree (no root: no blocking/attribution)
```

Layout: `usbwatch/` is the Python package (stdlib only). `packaging/` holds the systemd, OpenRC, SysV,
deb, rpm, logrotate and desktop files. `scripts/` holds install, uninstall and the package builders.
`tests/` holds the tests.

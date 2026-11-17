# Configuration

## Two places

| Where | Who can change it | What |
|---|---|---|
| `/etc/usbwatch/usbwatch.conf` (root:usbwatch, 0640) | root only | paths, logging, **web console exposure** (bind, allow-list, host names, TLS, session time, lock-out), monitor tuning |
| Console → Settings / Access Control (stored in the database) | signed-in console users | policy mode and scope, whitelist/blacklist, read/exec logging, read de-duplication, processes to ignore, SHA-256 hashing, recovery vault, retention |

After you edit the file, restart the services:
`sudo systemctl restart usbwatch usbwatch-web`, or `rc-service ... restart`, or `service ... restart`.
Changes made in the console take effect within about a second, with no restart.

## Opening the console to other machines

The default is local only. To reach the console from an admin workstation, set `bind` and `allow` and turn
on TLS:

```ini
[web]
bind = 0.0.0.0                    ; or one interface address, e.g. 192.168.1.20
port = 8790
allow = 127.0.0.1, ::1, 192.168.1.50, 10.10.0.0/24
allowed_hosts = usbwatch-pc.lab.local, 192.168.1.20
tls_cert = /etc/usbwatch/tls.crt
tls_key = /etc/usbwatch/tls.key
```

```bash
sudo openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj /CN=usbwatch-pc.lab.local \
     -addext "subjectAltName=DNS:usbwatch-pc.lab.local,IP:192.168.1.20" \
     -keyout /etc/usbwatch/tls.key -out /etc/usbwatch/tls.crt
sudo chgrp usbwatch /etc/usbwatch/tls.key && sudo chmod 640 /etc/usbwatch/tls.key
sudo systemctl restart usbwatch-web
```

- `allow` is checked on the TCP connection, before any HTTP. Loopback is always allowed. `any` allows
  every client, which is not recommended.
- `allowed_hosts` lists the names or IPs typed in the browser's address bar. Any other `Host` gets HTTP 421.
  This stops DNS-rebinding attacks.
- Without TLS on a non-loopback address, the service logs a warning, because passwords would cross the
  network in clear text.
- Remember the host firewall. With ufw, for example: `sudo ufw allow from 192.168.1.50 to any port 8790 proto tcp`.

## Console users

All console users are administrators. Every sign-in and change is written to the audit log.

```bash
sudo usbwatch passwd              # change admin's password (or create 'admin')
sudo usbwatch passwd alice        # create user alice / change her password
usbwatch users                    # list
sudo usbwatch userdel alice       # remove (the last user cannot be removed)
```

Passwords need at least 10 characters. Changing a password signs that user out everywhere.

## Recovery vault and hashing

- **Vault** (off by default): files written to a USB drive are copied to `/var/lib/usbwatch/vault`, which
  only root can read, within a per-file and a total size limit. When the oldest copies push the total over
  the limit, they are deleted. Deleted files can then be restored from **Deleted Files** while the drive is
  plugged in. Restores never overwrite: the restored copy gets a "(restored)" suffix.
- **SHA-256** (off by default; 0 MB): files written to USB up to the given size are hashed, and the hash is
  stored with the event and shown in CSV exports. This helps match a leaked file to a transfer.

## Reducing noise

Desktop indexers and thumbnailers read every file on a newly mounted drive. The default ignore list
(Settings → Monitoring) covers GNOME tracker/localsearch, KDE baloo, gvfs, tumbler, updatedb and similar
tools. Add any others that show up in **Transfers** as unwanted reads. Process names are matched against
the kernel's 15-character `comm` name and the executable's file name. A file read repeatedly by the same
process is reported once per de-duplication window (30 s by default).

## Files and paths

| Path | Owner / mode | Content |
|---|---|---|
| `/usr/local/bin/usbwatch` (`/usr/bin` for packages) | root 0755 | launcher |
| `/usr/local/lib/usbwatch/` | root 0644 | Python package + web assets |
| `/etc/usbwatch/usbwatch.conf` | root:usbwatch 0640 | configuration |
| `/etc/usbwatch/initial-admin-password` | root 0600 | only when generated; deleted once changed |
| `/var/lib/usbwatch/usbwatch.db` (+ `-wal`, `-shm`) | root:usbwatch 0660, dir 2770 | events, devices, policy, users, sessions, audit |
| `/var/lib/usbwatch/vault/` | root 0700 | recovery copies |
| `/var/log/usbwatch/usbwatch.log` | root:usbwatch | daemon diagnostics (rotated at 5 MB × 5) |
| `/var/log/usbwatch/events.jsonl` | root:usbwatch 0640 | one JSON event per line (logrotate weekly × 12) |
| `usbwatch.service`, `usbwatch-web.service` | systemd units | or `/etc/init.d/usbwatch{,-web}` for OpenRC / SysV |

## Environment variables (testing)

- `USBWATCH_CONF` selects another config file.
- `USBWATCH_DATA` points the data and log paths at a scratch folder. `make run-dev` uses both.

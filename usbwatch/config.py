"""Static configuration (/etc/usbwatch/usbwatch.conf).

Only root can edit this file. It holds everything that changes how far the web console is exposed
(bind address, client allow-list, TLS), so the console can never widen its own exposure.
Monitoring/policy settings that admins change day to day live in the database (see db.DEFAULTS).
"""
import os
import configparser
import ipaddress

CONF_FILE = os.environ.get("USBWATCH_CONF", "/etc/usbwatch/usbwatch.conf")

DEFAULTS = {
    "paths": {
        "data_dir": "/var/lib/usbwatch",
        "log_dir": "/var/log/usbwatch",
    },
    "web": {
        "enabled": "yes",
        "bind": "127.0.0.1",
        "port": "8790",
        "allow": "127.0.0.1, ::1",
        "allowed_hosts": "",
        "tls_cert": "",
        "tls_key": "",
        "session_hours": "8",
        "max_failed_logins": "10",
    },
    "monitor": {
        "poll_interval": "1.0",
        "process_attribution": "yes",
        "max_watches": "200000",
        "skip_dirs": "System Volume Information, $RECYCLE.BIN, lost+found, .Trash-*, .Spotlight-V100, .fseventsd",
    },
    "logging": {
        "level": "info",
        "events_file": "/var/log/usbwatch/events.jsonl",
        "syslog": "no",
    },
}


def _split(v):
    return [x.strip() for x in (v or "").replace("\n", ",").split(",") if x.strip()]


class Config:
    def __init__(self, path=CONF_FILE):
        self.path = path
        self.cp = configparser.ConfigParser(interpolation=None)
        self.cp.read_dict(DEFAULTS)
        self.loaded = bool(self.cp.read(path))
        env = os.environ.get("USBWATCH_DATA")          # handy for testing without root
        if env:
            self.cp.set("paths", "data_dir", env)
            self.cp.set("paths", "log_dir", os.path.join(env, "log"))
            if self.cp.get("logging", "events_file").startswith("/var/log/usbwatch/"):
                self.cp.set("logging", "events_file", os.path.join(env, "log", "events.jsonl"))

    def get(self, sec, key):
        return self.cp.get(sec, key, fallback=DEFAULTS.get(sec, {}).get(key, "")).strip()

    def getint(self, sec, key):
        try:
            return int(self.get(sec, key))
        except ValueError:
            return int(DEFAULTS[sec][key])

    def getfloat(self, sec, key):
        try:
            return float(self.get(sec, key))
        except ValueError:
            return float(DEFAULTS[sec][key])

    def getbool(self, sec, key):
        return self.get(sec, key).lower() in ("1", "yes", "true", "on")

    def getlist(self, sec, key):
        return _split(self.get(sec, key))

    # ---- derived paths ----
    @property
    def data_dir(self):
        return self.get("paths", "data_dir")

    @property
    def log_dir(self):
        return self.get("paths", "log_dir")

    @property
    def db_path(self):
        return os.path.join(self.data_dir, "usbwatch.db")

    @property
    def vault_dir(self):
        return os.path.join(self.data_dir, "vault")

    # ---- web exposure ----
    def bind_addresses(self):
        return self.getlist("web", "bind") or ["127.0.0.1"]

    def allow_networks(self):
        """Client networks allowed to open a connection. Loopback is always allowed."""
        nets = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
        for item in self.getlist("web", "allow"):
            if item.lower() in ("any", "all", "*"):
                return [ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")]
            try:
                nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                pass
        return nets

    def allowed_hosts(self):
        """Host header values accepted (stops DNS-rebinding attacks on the localhost console)."""
        hosts = {"localhost", "127.0.0.1", "::1", "[::1]", "ip6-localhost"}
        for b in self.bind_addresses():
            if b not in ("0.0.0.0", "::"):
                hosts.add(b)
                hosts.add("[%s]" % b if ":" in b else b)
        hosts.update(h.lower() for h in self.getlist("web", "allowed_hosts"))
        return hosts

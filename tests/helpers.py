import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def temp_config(extra=""):
    """A Config pointing at a throw-away data dir and config file."""
    from usbwatch.config import Config
    d = tempfile.mkdtemp(prefix="usbwatch-test-")
    conf = os.path.join(d, "usbwatch.conf")
    with open(conf, "w") as f:
        f.write("[paths]\ndata_dir = %s/data\nlog_dir = %s/log\n[logging]\nevents_file = %s/log/events.jsonl\n%s"
                % (d, d, d, extra))
    os.makedirs(os.path.join(d, "data"))
    os.makedirs(os.path.join(d, "log"))
    return Config(conf), d

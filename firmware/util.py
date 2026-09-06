"""Small shared utilities: timestamps, file hashes, logging setup."""

import datetime
import hashlib
import logging
import sys
from pathlib import Path


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


_LOGGER_CONFIGURED = False


def setup_logging(log_dir="logs", level="INFO", stream=None, log_file="orchestrator.log",
                  force=False):
    """Configure the 'f1' logger to write to both a file and stdout."""
    global _LOGGER_CONFIGURED
    if _LOGGER_CONFIGURED and not force:
        return logging.getLogger("f1")
    root = logging.getLogger("f1")
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S%z")
    if stream is None:
        stream = sys.stdout
    sh = logging.StreamHandler(stream)
    sh.setFormatter(fmt)
    root.addHandler(sh)
    try:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(Path(log_dir) / log_file), encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        pass
    root.propagate = False
    _LOGGER_CONFIGURED = True
    return root
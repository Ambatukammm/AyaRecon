"""
AyaRecon — shared helpers.
Made by Ruel.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import sys
import time
import threading
from typing import Callable
from urllib.parse import urlparse


# --------------------------------------------------------------- privilege check
def is_admin() -> bool:
    """True if the process is elevated (Administrator on Windows, root elsewhere)."""
    try:
        if sys.platform.startswith("win"):
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# --------------------------------------------------- running-process registry
# Long scans (nmap, tshark) register their Popen here so a "Stop" can kill them.
_PROCS: set = set()
_PROC_LOCK = threading.Lock()


def register_proc(proc) -> None:
    with _PROC_LOCK:
        _PROCS.add(proc)


def unregister_proc(proc) -> None:
    with _PROC_LOCK:
        _PROCS.discard(proc)


def terminate_all_procs() -> int:
    """Terminate every registered subprocess. Returns how many were signalled."""
    with _PROC_LOCK:
        procs = list(_PROCS)
        _PROCS.clear()
    n = 0
    for p in procs:
        try:
            if p.poll() is None:
                p.terminate()
                n += 1
        except Exception:
            pass
    return n

Finding = dict  # alias for readability

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)


def normalise_target(target: str) -> str:
    """Strip scheme/path, return a bare host or IP."""
    target = (target or "").strip()
    if not target:
        return ""
    if "://" in target:
        target = urlparse(target).netloc or urlparse(target).path
    # strip any port / path remnants
    target = target.split("/")[0].split(":")[0]
    return target.strip().lower()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value or ""))


def is_valid_target(value: str) -> bool:
    v = normalise_target(value)
    return is_ip(v) or is_domain(v)


def resolve(host: str) -> list[str]:
    """Resolve a hostname to a list of IP strings (best-effort)."""
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except (socket.gaierror, OSError):
        return []


class RateLimiter:
    """Simple token-bucket-ish limiter: at most `per_sec` acquisitions/second."""

    def __init__(self, per_sec: float):
        self.min_interval = 1.0 / per_sec if per_sec > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


def safe_call(fn: Callable, *args, default=None, **kwargs):
    """Run fn, swallow exceptions, return default on failure. Keeps scans resilient."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        return default


# Common TCP ports -> service name (for quick labelling without a full nmap db)
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 5985: "winrm", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

TOP_100_PORTS = sorted(COMMON_PORTS.keys()) + [
    20, 69, 123, 161, 389, 636, 1080, 1194, 1723, 3000, 3128, 4444, 5000,
    5060, 5601, 7001, 8000, 8008, 8081, 8888, 9000, 9090, 9443, 10000, 11211,
    50000,
]
TOP_100_PORTS = sorted(set(TOP_100_PORTS))[:100]

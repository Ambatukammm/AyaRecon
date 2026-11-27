"""
AyaRecon — PART 3: Enumeration modules (locked behind the permission gate).
Made by Ruel.

SCOPE NOTE (read me):
---------------------
This module performs *resource discovery* — finding which hostnames and URL
paths exist on a target by trying names from a wordlist. This is standard,
widely-used reconnaissance (comparable to gobuster / ffuf / dirsearch) and is
how defenders find their own forgotten admin panels, backups and exposed
files before an attacker does.

It deliberately does NOT include online credential / password brute-forcing
against login or HTTP-auth endpoints. That capability is an authentication
attack rather than a self-audit function, so AyaRecon does not ship it. If you need
to test your own login's resistance to weak passwords, do that against an
account you control using a dedicated, consented process — not by hammering a
live auth endpoint through this tool.

Everything here:
  • is locked until the "I HAVE PERMISSION" gate is unlocked,
  • is rate-limited (configurable) to avoid overwhelming a target,
  • logs every run to the permission audit table via the orchestrator.
"""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
from typing import Callable, Iterable

from ..util import Finding, normalise_target, resolve, RateLimiter, safe_call

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


# A small built-in wordlist so the tool is usable out of the box. Users can
# point AyaRecon at a larger custom list (e.g. SecLists) in Settings.
BUILTIN_DIR_WORDS = [
    "admin", "administrator", "login", "dashboard", "config", "backup",
    "backups", "old", "test", "dev", "staging", ".git", ".env", "api",
    "uploads", "files", "images", "assets", "static", "wp-admin", "wp-login.php",
    "phpmyadmin", "server-status", "robots.txt", "sitemap.xml", ".well-known",
    "private", "tmp", "logs", "db", "database", "sql", "data", "download",
    "user", "users", "account", "secret", "secrets", "credentials",
]

BUILTIN_SUBDOMAIN_WORDS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dev", "staging", "test", "api", "admin", "portal", "vpn", "remote",
    "gateway", "app", "apps", "secure", "shop", "store", "blog", "cdn",
    "static", "assets", "img", "media", "git", "gitlab", "jenkins", "jira",
    "confluence", "db", "database", "mysql", "intranet", "internal", "beta",
]


def load_wordlist(path: str | None, fallback: list[str]) -> list[str]:
    """Load a custom wordlist if provided and valid, else use the builtin list."""
    if path:
        p = Path(path)
        if p.exists():
            try:
                words = [w.strip() for w in p.read_text(encoding="utf-8",
                         errors="ignore").splitlines() if w.strip()
                         and not w.startswith("#")]
                if words:
                    return words
            except OSError:
                pass
    return list(fallback)


# --------------------------------------------------------------- directory discovery
def directory_enum(
    target: str,
    wordlist: list[str] | None = None,
    rate_per_sec: float = 20.0,
    timeout: float = 8.0,
    max_threads: int = 20,
    progress: Callable[[int, int], None] | None = None,
) -> list[Finding]:
    """Discover existing paths by requesting each word and checking the status."""
    host = normalise_target(target)
    if requests is None:
        return [_f("enum", "Directory enum unavailable", "Install requests first.")]

    words = wordlist or BUILTIN_DIR_WORDS
    limiter = RateLimiter(rate_per_sec)
    base = _base_url(host)
    findings: list[Finding] = []
    total = len(words)
    done = 0

    def check(word: str):
        limiter.wait()
        url = f"{base}/{word.lstrip('/')}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False,
                                headers={"User-Agent": "AyaRecon/3.0 (by Ruel)"})
        except Exception:
            return None
        code = resp.status_code
        # 200/301/302/401/403 all indicate the path *exists* in some form.
        if code in (200, 204, 301, 302, 307, 401, 403):
            return (url, code, len(resp.content))
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = [pool.submit(check, w) for w in words]
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if progress:
                safe_call(progress, done, total)
            res = fut.result()
            if res:
                url, code, size = res
                sev = "info"
                low = url.lower()
                if code in (401, 403):
                    sev = "medium"      # protected but present -> interesting
                if any(s in low for s in (".git", ".env", "backup", "secret",
                                          "credentials", "config", "sql", "phpmyadmin")):
                    sev = "high"        # sensitive path exposed
                findings.append(_f("enum", f"Path found [{code}]",
                                   f"{url} ({code}, {size} bytes)",
                                   {"url": url, "status": code, "size": size},
                                   severity=sev))
    if not findings:
        findings.append(_f("enum", "No paths discovered",
                           f"{base} ({total} words tried)"))
    return findings


# --------------------------------------------------------------- subdomain discovery
def subdomain_enum(
    target: str,
    wordlist: list[str] | None = None,
    rate_per_sec: float = 20.0,
    max_threads: int = 30,
    progress: Callable[[int, int], None] | None = None,
) -> list[Finding]:
    """Discover live subdomains by resolving each candidate hostname (DNS only)."""
    host = normalise_target(target)
    words = wordlist or BUILTIN_SUBDOMAIN_WORDS
    limiter = RateLimiter(rate_per_sec)
    findings: list[Finding] = []
    total = len(words)
    done = 0

    def check(word: str):
        limiter.wait()
        fqdn = f"{word}.{host}"
        ips = resolve(fqdn)
        return (fqdn, ips) if ips else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = [pool.submit(check, w) for w in words]
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if progress:
                safe_call(progress, done, total)
            res = fut.result()
            if res:
                fqdn, ips = res
                findings.append(_f("enum", "Subdomain resolved",
                                   f"{fqdn} -> {', '.join(ips)}",
                                   {"host": fqdn, "ips": ips}))
    if not findings:
        findings.append(_f("enum", "No subdomains resolved",
                           f"{host} ({total} candidates tried)"))
    return findings


# --------------------------------------------------------------------------- helpers
def _base_url(host: str) -> str:
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    return f"https://{host}".rstrip("/")


def _f(category: str, title: str, detail: str = "",
       data: dict | None = None, severity: str = "info") -> Finding:
    return {"category": category, "title": title, "detail": detail,
            "data": data or {}, "severity": severity}


ENUM_CHECKS = {
    "Directory / file discovery": directory_enum,
    "Subdomain discovery (wordlist)": subdomain_enum,
}

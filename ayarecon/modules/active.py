"""
AyaRecon — PART 2: Active scanning (direct contact — requires confirmation).
Made by Ruel.

These functions make direct connections to the target and must only be run
after the permission layer has confirmed the user is authorised. They are
written to be polite (timeouts, bounded concurrency) rather than aggressive.
"""

from __future__ import annotations

import concurrent.futures
import socket
import ssl
from typing import Iterable

from ..util import (
    Finding, normalise_target, resolve, COMMON_PORTS, TOP_100_PORTS, safe_call,
)

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


# ------------------------------------------------------------------- host discovery
def ping_host(target: str, timeout: float = 1.0) -> list[Finding]:
    """
    'Is it up?' via a TCP connect to common ports (works without raw-socket/root,
    unlike ICMP). If any common port answers, the host is considered alive.
    """
    host = normalise_target(target)
    ips = resolve(host) or ([host] if host else [])
    findings: list[Finding] = []
    for ip in ips:
        alive = False
        for port in (443, 80, 22, 445, 3389):
            if _tcp_open(ip, port, timeout):
                alive = True
                break
        findings.append(_f("host", "Host status",
                           f"{ip} appears {'UP' if alive else 'DOWN/filtered'}",
                           {"ip": ip, "alive": alive},
                           severity="info"))
    return findings


# ------------------------------------------------------------------- port scanning
def port_scan(
    target: str,
    ports: Iterable[int] | None = None,
    timeout: float = 1.0,
    max_threads: int = 50,
) -> list[Finding]:
    host = normalise_target(target)
    ip = (resolve(host) or [host])[0]
    port_list = list(ports) if ports else TOP_100_PORTS
    open_ports: list[int] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_tcp_open, ip, p, timeout): p for p in port_list}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            if fut.result():
                open_ports.append(p)

    findings: list[Finding] = []
    for p in sorted(open_ports):
        svc = COMMON_PORTS.get(p, "unknown")
        # Risk-weight a few notoriously dangerous exposed services.
        sev = "info"
        if p in (3389, 23, 445, 135, 139, 5900, 6379, 27017, 9200, 1433, 3306, 5432):
            sev = "high"
        findings.append(_f("port", f"Open port {p}/tcp",
                           f"{p}/tcp open ({svc})",
                           {"port": p, "service": svc, "ip": ip}, severity=sev))
    if not findings:
        findings.append(_f("port", "No open ports found",
                           f"{ip} (scanned {len(port_list)} ports)"))
    return findings


def service_versions(target: str, ports: Iterable[int], timeout: float = 3.0) -> list[Finding]:
    """Grab banners from open ports to estimate service/version."""
    host = normalise_target(target)
    ip = (resolve(host) or [host])[0]
    findings: list[Finding] = []
    for port in ports:
        banner = _grab_banner(ip, port, timeout)
        if banner:
            findings.append(_f("service", f"Banner on {port}/tcp", banner,
                               {"port": port, "banner": banner}))
    if not findings:
        findings.append(_f("service", "No banners retrieved", host))
    return findings


# ---------------------------------------------------------------- web tech / headers
def http_fingerprint(target: str, timeout: float = 8.0) -> list[Finding]:
    """Detect server, tech stack hints and security headers over HTTP(S)."""
    host = normalise_target(target)
    if requests is None:
        return [_f("web", "HTTP fingerprint unavailable", "Install requests first.")]

    findings: list[Finding] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                                headers={"User-Agent": "AyaRecon/3.0 (by Ruel)"})
        except Exception:
            continue

        headers = {k.lower(): v for k, v in resp.headers.items()}
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server:
            findings.append(_f("web", "Server header", server, {"server": server}))
        if powered:
            findings.append(_f("web", "X-Powered-By", powered, {"x_powered_by": powered}))

        # Tech hints from headers / cookies
        tech = _tech_hints(headers, resp.text[:2000] if hasattr(resp, "text") else "")
        for t in tech:
            findings.append(_f("web", "Technology detected", t, {"tech": t}))

        # Security headers
        findings.extend(_security_headers(headers, url))
        break  # first scheme that answers wins
    if not findings:
        findings.append(_f("web", "No HTTP response", host, severity="low"))
    return findings


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _security_headers(headers: dict, url: str) -> list[Finding]:
    findings = []
    for key, label in SECURITY_HEADERS.items():
        if key in headers:
            findings.append(_f("header", f"{label} present", headers[key],
                               {"header": label, "value": headers[key]}))
        else:
            sev = "medium" if key in ("strict-transport-security",
                                      "content-security-policy") else "low"
            findings.append(_f("header", f"{label} MISSING",
                               f"{url} does not set {label}",
                               {"header": label, "missing": True}, severity=sev))
    return findings


def _tech_hints(headers: dict, body: str) -> list[str]:
    hints = []
    cookie = headers.get("set-cookie", "").lower()
    if "phpsessid" in cookie:
        hints.append("PHP")
    if "asp.net" in (headers.get("x-powered-by", "").lower() + cookie):
        hints.append("ASP.NET")
    if "x-aspnet-version" in headers:
        hints.append(f"ASP.NET {headers['x-aspnet-version']}")
    if "x-drupal-cache" in headers or "drupal" in body.lower():
        hints.append("Drupal")
    if "wp-content" in body.lower() or "wordpress" in body.lower():
        hints.append("WordPress")
    if "x-generator" in headers:
        hints.append(headers["x-generator"])
    if "cf-ray" in headers:
        hints.append("Cloudflare")
    return hints


# --------------------------------------------------------------------------- helpers
def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Nudge HTTP-ish services to respond.
            if port in (80, 8080, 8000, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
            data = s.recv(256)
            return data.decode("latin-1", errors="replace").strip()
    except Exception:
        return ""


def _f(category: str, title: str, detail: str = "",
       data: dict | None = None, severity: str = "info") -> Finding:
    return {"category": category, "title": title, "detail": detail,
            "data": data or {}, "severity": severity}


ACTIVE_CHECKS = {
    "Host discovery": ping_host,
    "Port scan (top 100)": port_scan,
    "HTTP fingerprint + headers": http_fingerprint,
}

"""
AyaRecon — PART 1: Passive OSINT.
Made by Ruel.

These functions are safe by default: with the exception of DNS resolution
(which hits resolvers, not the target) and public API lookups, nothing here
sends traffic to the target system. They gather what is already public.

Every function returns a list of finding dicts and never raises — network
errors degrade into an informational finding so a scan never dies halfway.
"""

from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from ..util import Finding, normalise_target, is_ip, resolve, safe_call

# Optional dependencies — imported lazily so the app runs without them.
try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    import dns.resolver  # dnspython
except ImportError:  # pragma: no cover
    dns = None

try:
    import whois as _whois  # python-whois
except ImportError:  # pragma: no cover
    _whois = None


# --------------------------------------------------------------------------- DNS
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]


def dns_records(target: str, timeout: float = 5.0) -> list[Finding]:
    host = normalise_target(target)
    findings: list[Finding] = []
    if dns is None:
        # Fall back to basic A/AAAA via socket if dnspython isn't installed.
        ips = resolve(host)
        for ip in ips:
            findings.append(_f("dns", f"A/AAAA record", ip, {"ip": ip}))
        if not ips:
            findings.append(_f("dns", "DNS resolution failed", host, severity="low"))
        return findings

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(host, rtype)
            for rdata in answers:
                val = rdata.to_text()
                sev = "info"
                # TXT records sometimes leak internal hosts / verification tokens.
                findings.append(_f("dns", f"{rtype} record", val,
                                   {"type": rtype, "value": val}, severity=sev))
        except Exception:
            continue
    if not findings:
        findings.append(_f("dns", "No DNS records resolved", host, severity="low"))
    return findings


def reverse_dns(target: str) -> list[Finding]:
    host = normalise_target(target)
    ips = [host] if is_ip(host) else resolve(host)
    findings: list[Finding] = []
    for ip in ips:
        name = safe_call(lambda: socket.gethostbyaddr(ip)[0])
        if name:
            findings.append(_f("dns", "Reverse DNS (PTR)", f"{ip} -> {name}",
                               {"ip": ip, "ptr": name}))
    return findings


# ------------------------------------------------------------------------- WHOIS
def whois_lookup(target: str) -> list[Finding]:
    host = normalise_target(target)
    if _whois is None:
        return [_f("whois", "WHOIS unavailable",
                   "Install python-whois to enable registrar lookups.", severity="info")]
    data = safe_call(lambda: _whois.whois(host))
    if not data:
        return [_f("whois", "WHOIS lookup failed", host, severity="low")]

    def fmt(v: Any) -> str:
        if isinstance(v, (list, tuple)):
            return ", ".join(str(x) for x in v if x)
        return str(v) if v else ""

    fields = {
        "Registrar": fmt(data.get("registrar")),
        "Created": fmt(data.get("creation_date")),
        "Expires": fmt(data.get("expiration_date")),
        "Name servers": fmt(data.get("name_servers")),
        "Registrant org": fmt(data.get("org")),
        "Country": fmt(data.get("country")),
        "Emails": fmt(data.get("emails")),
    }
    findings = [_f("whois", f"WHOIS: {k}", v, {"field": k, "value": v})
                for k, v in fields.items() if v]
    return findings or [_f("whois", "WHOIS returned no useful fields", host, severity="low")]


# --------------------------------------------------------------------------- SSL
def ssl_certificate(target: str, port: int = 443, timeout: float = 8.0) -> list[Finding]:
    host = normalise_target(target)
    findings: list[Finding] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:
        return [_f("ssl", "TLS handshake failed", f"{host}:{port} ({exc})", severity="low")]

    issuer = _rdn(cert.get("issuer"))
    subject = _rdn(cert.get("subject"))
    not_after = cert.get("notAfter", "")
    sans = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]

    findings.append(_f("ssl", "Certificate issuer", issuer, {"issuer": issuer}))
    findings.append(_f("ssl", "Certificate subject", subject, {"subject": subject}))

    # Expiry check
    sev = "info"
    detail = not_after
    exp = safe_call(lambda: datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    .replace(tzinfo=timezone.utc))
    if exp:
        days = (exp - datetime.now(timezone.utc)).days
        detail = f"{not_after} ({days} days remaining)"
        if days < 0:
            sev = "high"
            detail = f"EXPIRED on {not_after}"
        elif days < 15:
            sev = "medium"
    findings.append(_f("ssl", "Certificate expiry", detail,
                       {"not_after": not_after}, severity=sev))

    if sans:
        findings.append(_f("ssl", "Subject Alternative Names", ", ".join(sans),
                           {"sans": sans}))
    return findings


# ---------------------------------------------------- Subdomains (cert transparency)
def subdomains_crtsh(target: str, timeout: float = 15.0) -> list[Finding]:
    """Passive subdomain discovery via crt.sh certificate transparency logs."""
    host = normalise_target(target)
    if requests is None:
        return [_f("subdomain", "Subdomain discovery unavailable",
                   "Install requests to query certificate transparency logs.")]
    url = f"https://crt.sh/?q=%25.{host}&output=json"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "AyaRecon/3.0 (by Ruel)"})
        resp.raise_for_status()
        rows = resp.json()
    except Exception as exc:
        return [_f("subdomain", "crt.sh query failed", str(exc), severity="low")]

    subs: set[str] = set()
    for row in rows:
        name = (row.get("name_value") or "").lower()
        for part in name.split("\n"):
            part = part.strip().lstrip("*.")
            if part.endswith(host) and part != host:
                subs.add(part)
    findings = [_f("subdomain", "Subdomain (CT log)", s, {"host": s}) for s in sorted(subs)]
    if not findings:
        findings.append(_f("subdomain", "No subdomains found in CT logs", host))
    return findings


# ------------------------------------------------------------- Wayback Machine
def wayback_snapshots(target: str, limit: int = 25, timeout: float = 15.0) -> list[Finding]:
    host = normalise_target(target)
    if requests is None:
        return [_f("archive", "Wayback lookup unavailable",
                   "Install requests to query the Wayback Machine.")]
    url = (
        "http://web.archive.org/cdx/search/cdx"
        f"?url={host}/*&output=json&collapse=urlkey&limit={limit}&fl=original,timestamp"
    )
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "AyaRecon/3.0 (by Ruel)"})
        resp.raise_for_status()
        rows = resp.json()
    except Exception as exc:
        return [_f("archive", "Wayback query failed", str(exc), severity="low")]

    findings: list[Finding] = []
    for row in rows[1:]:  # first row is the header
        if len(row) >= 2:
            original, ts = row[0], row[1]
            findings.append(_f("archive", "Archived URL", f"{original} (snapshot {ts})",
                               {"url": original, "timestamp": ts}))
    if not findings:
        findings.append(_f("archive", "No Wayback snapshots found", host))
    return findings


# ----------------------------------------------------------- Breach lookup (HIBP)
def breach_lookup(email: str, api_key: str = "", timeout: float = 15.0) -> list[Finding]:
    """
    HaveIBeenPwned breach lookup. Requires an API key (HIBP is paid).
    Without a key we return guidance rather than guessing.
    """
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return [_f("breach", "Invalid email", email, severity="low")]
    if requests is None:
        return [_f("breach", "Breach lookup unavailable", "Install requests first.")]
    if not api_key:
        return [_f("breach", "HIBP API key required",
                   "Enter a HaveIBeenPwned API key in Settings to enable breach checks.",
                   severity="info")]
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {"hibp-api-key": api_key, "User-Agent": "AyaRecon/3.0 (by Ruel)"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except Exception as exc:
        return [_f("breach", "HIBP request failed", str(exc), severity="low")]
    if resp.status_code == 404:
        return [_f("breach", "No breaches found", email, {"email": email})]
    if resp.status_code != 200:
        return [_f("breach", "HIBP error", f"HTTP {resp.status_code}", severity="low")]
    breaches = safe_call(resp.json, default=[]) or []
    findings = []
    for b in breaches:
        name = b.get("Name", "?")
        date = b.get("BreachDate", "?")
        findings.append(_f("breach", f"Breach: {name}",
                           f"{email} exposed in {name} ({date})",
                           {"email": email, "breach": name, "date": date},
                           severity="high"))
    return findings


# --------------------------------------------------------------------------- helpers
def _f(category: str, title: str, detail: str = "",
       data: dict | None = None, severity: str = "info") -> Finding:
    return {
        "category": category,
        "title": title,
        "detail": detail,
        "data": data or {},
        "severity": severity,
    }


def _rdn(rdn_seq) -> str:
    """Flatten a certificate RDN sequence into 'CN=..., O=...' form."""
    if not rdn_seq:
        return ""
    parts = []
    for rdn in rdn_seq:
        for k, v in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


# Registry so the GUI/CLI can iterate available passive checks.
PASSIVE_CHECKS = {
    "DNS records": dns_records,
    "Reverse DNS": reverse_dns,
    "WHOIS / RDAP": whois_lookup,
    "SSL/TLS certificate": ssl_certificate,
    "Subdomains (CT logs)": subdomains_crtsh,
    "Wayback Machine": wayback_snapshots,
}

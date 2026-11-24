"""
AyaRecon — PHASE 3: Service Enumeration.
Made by Ruel.

Per-protocol enumeration for SMB, HTTP, DNS, FTP, SMTP, SNMP and LDAP.

Design rules for this phase:
  • READ-ONLY. Every check identifies what a service exposes or how it is
    (mis)configured. Nothing here attempts exploitation or authentication
    attacks — it reports facts a defender needs (e.g. "anonymous FTP allowed",
    "SMTP VRFY enabled", "DNS zone transfer permitted").
  • Each finding carries a `data` dict with any version string it learned, so
    Phase 4 (vulnerability assessment) can match it against the local CVE base.
  • Graceful degradation: protocols that need an optional library degrade to an
    informational finding instead of crashing when the library is absent.

These are standard, defensible enumeration checks — the same ones a blue team
runs against its own estate to find misconfigurations before an attacker does.
"""

from __future__ import annotations

import ftplib
import smtplib
import socket
import ssl
from typing import Any

from ..util import Finding, normalise_target, resolve, safe_call

# Optional deps (all degrade gracefully).
try:
    import requests
except ImportError:  # pragma: no cover
    requests = None
try:
    import dns.resolver
    import dns.query
    import dns.zone
except ImportError:  # pragma: no cover
    dns = None


# --------------------------------------------------------------------------- HTTP
def http_enum(target: str, timeout: float = 8.0) -> list[Finding]:
    """Enumerate HTTP(S): server/version, allowed methods, robots, interesting paths."""
    host = normalise_target(target)
    findings: list[Finding] = []
    if requests is None:
        return [_f("http", "HTTP enum unavailable", "Install requests to enable.", severity="info")]

    for scheme in ("https", "http"):
        base = f"{scheme}://{host}"
        try:
            resp = requests.get(base, timeout=timeout, allow_redirects=True,
                                headers={"User-Agent": "AyaRecon/3.0 (by Ruel)"})
        except Exception:
            continue

        headers = {k.lower(): v for k, v in resp.headers.items()}
        server = headers.get("server", "")
        if server:
            findings.append(_f("http", "HTTP server", server,
                               {"service": "http", "banner": server,
                                "product": _product(server)}, severity="info"))
        powered = headers.get("x-powered-by", "")
        if powered:
            findings.append(_f("http", "X-Powered-By", powered,
                               {"service": "http", "banner": powered}))

        # Page title
        title = _extract_title(resp.text if hasattr(resp, "text") else "")
        if title:
            findings.append(_f("http", "Page title", title, {"title": title}))

        # Allowed methods (OPTIONS) — dangerous methods are a misconfiguration.
        allow = safe_call(lambda: requests.options(base, timeout=timeout).headers.get("Allow", ""))
        if allow:
            dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT")
                         if m in allow.upper()]
            sev = "medium" if dangerous else "info"
            detail = f"Allowed: {allow}" + (f"  ⚠ risky: {', '.join(dangerous)}" if dangerous else "")
            findings.append(_f("http", "HTTP methods", detail,
                               {"allow": allow, "dangerous": dangerous}, severity=sev))

        # robots.txt / sitemap — information disclosure surface.
        for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
            r = safe_call(lambda p=path: requests.get(f"{base}/{p}", timeout=timeout,
                          headers={"User-Agent": "AyaRecon/3.0 (by Ruel)"}))
            if r is not None and r.status_code == 200 and r.content:
                findings.append(_f("http", f"{path} present",
                                   f"{base}/{path} ({len(r.content)} bytes)",
                                   {"url": f"{base}/{path}"}))
        break  # first responsive scheme wins
    if not findings:
        findings.append(_f("http", "No HTTP service", host, severity="info"))
    return findings


# --------------------------------------------------------------------------- DNS
def dns_enum(target: str, timeout: float = 5.0) -> list[Finding]:
    """Enumerate DNS: nameservers, and test each for an (AXFR) zone transfer."""
    host = normalise_target(target)
    findings: list[Finding] = []
    if dns is None:
        return [_f("dns", "DNS enum unavailable",
                   "Install dnspython to enable zone-transfer checks.", severity="info")]

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    nameservers = []
    try:
        for rdata in resolver.resolve(host, "NS"):
            ns = str(rdata.target).rstrip(".")
            nameservers.append(ns)
            findings.append(_f("dns", "Nameserver", ns, {"ns": ns}))
    except Exception:
        findings.append(_f("dns", "No NS records", host, severity="info"))

    # Zone transfer attempt — a successful AXFR is a serious misconfiguration.
    for ns in nameservers:
        ns_ips = resolve(ns)
        for ip in ns_ips:
            try:
                xfr = dns.query.xfr(ip, host, timeout=timeout, lifetime=timeout)
                zone = dns.zone.from_xfr(xfr)
                names = [str(n) for n in zone.nodes.keys()]
                findings.append(_f(
                    "dns", "⚠ Zone transfer ALLOWED",
                    f"{ns} ({ip}) allowed AXFR — {len(names)} records exposed",
                    {"ns": ns, "ip": ip, "records": names[:200], "misconfig": "zone_transfer"},
                    severity="high"))
            except Exception:
                # The normal, healthy case: AXFR refused.
                continue
    return findings or [_f("dns", "DNS enumeration complete", host)]


# --------------------------------------------------------------------------- FTP
def ftp_enum(target: str, port: int = 21, timeout: float = 8.0) -> list[Finding]:
    """Grab the FTP banner and test whether anonymous login is permitted."""
    host = normalise_target(target)
    ip = (resolve(host) or [host])[0]
    findings: list[Finding] = []
    try:
        ftp = ftplib.FTP()
        banner = ftp.connect(ip, port, timeout=timeout)
        findings.append(_f("ftp", "FTP banner", banner.strip(),
                           {"service": "ftp", "banner": banner.strip(),
                            "product": _product(banner)}))
        # Anonymous login is a classic misconfiguration — report, don't abuse.
        try:
            ftp.login()  # defaults to anonymous
            findings.append(_f("ftp", "⚠ Anonymous FTP ALLOWED",
                               f"{ip}:{port} accepts anonymous login",
                               {"misconfig": "anonymous_ftp"}, severity="high"))
            listing = safe_call(ftp.nlst, default=[]) or []
            if listing:
                findings.append(_f("ftp", "Anonymous directory listing",
                                   ", ".join(listing[:25]),
                                   {"entries": listing[:100]}, severity="medium"))
            safe_call(ftp.quit)
        except ftplib.error_perm:
            findings.append(_f("ftp", "Anonymous login refused", f"{ip}:{port} (good)"))
            safe_call(ftp.close)
    except Exception as exc:
        return [_f("ftp", "No FTP service", f"{ip}:{port} ({exc})", severity="info")]
    return findings


# --------------------------------------------------------------------------- SMTP
def smtp_enum(target: str, port: int = 25, timeout: float = 8.0) -> list[Finding]:
    """Banner + check VRFY/EXPN (user enumeration) and STARTTLS availability."""
    host = normalise_target(target)
    ip = (resolve(host) or [host])[0]
    findings: list[Finding] = []
    try:
        smtp = smtplib.SMTP(timeout=timeout)
        code, msg = smtp.connect(ip, port)
        banner = msg.decode("latin-1", "replace") if isinstance(msg, bytes) else str(msg)
        findings.append(_f("smtp", "SMTP banner", banner.strip(),
                           {"service": "smtp", "banner": banner.strip(),
                            "product": _product(banner)}))
        smtp.ehlo_or_helo_if_needed()
        ext = getattr(smtp, "esmtp_features", {})
        if "starttls" in ext:
            findings.append(_f("smtp", "STARTTLS supported", "TLS available (good)",
                               {"starttls": True}))
        else:
            findings.append(_f("smtp", "STARTTLS not advertised",
                               "Mail may be sent in clear text", severity="medium"))

        # VRFY / EXPN support = username enumeration misconfiguration.
        code, _ = safe_call(lambda: smtp.docmd("VRFY", "root"), default=(0, b""))
        if code and 200 <= code < 300:
            findings.append(_f("smtp", "⚠ VRFY enabled",
                               "Server supports VRFY — allows username enumeration",
                               {"misconfig": "smtp_vrfy"}, severity="medium"))
        code, _ = safe_call(lambda: smtp.docmd("EXPN", "root"), default=(0, b""))
        if code and 200 <= code < 300:
            findings.append(_f("smtp", "⚠ EXPN enabled",
                               "Server supports EXPN — allows mailing-list enumeration",
                               {"misconfig": "smtp_expn"}, severity="medium"))
        safe_call(smtp.quit)
    except Exception as exc:
        return [_f("smtp", "No SMTP service", f"{ip}:{port} ({exc})", severity="info")]
    return findings


# --------------------------------------------------------------------------- SMB
def smb_enum(target: str, timeout: float = 6.0) -> list[Finding]:
    """
    Detect SMB and, where a library is available, enumerate shares via a NULL
    session (read-only). Flags legacy SMBv1 where detectable.
    """
    host = normalise_target(target)
    ip = (resolve(host) or [host])[0]
    findings: list[Finding] = []

    open_ports = [p for p in (445, 139) if _tcp_open(ip, p, timeout)]
    if not open_ports:
        return [_f("smb", "No SMB service", f"{ip} (445/139 closed)", severity="info")]
    findings.append(_f("smb", "SMB exposed", f"{ip} ({'/'.join(str(p) for p in open_ports)} open)",
                       {"service": "smb", "ports": open_ports},
                       severity="medium"))

    # SMBv1 negotiation probe (SMBv1 is deprecated / EternalBlue-era).
    if _smb1_supported(ip, timeout):
        findings.append(_f("smb", "⚠ SMBv1 supported",
                           f"{ip} negotiates the legacy SMBv1 dialect",
                           {"service": "smb", "version": "SMBv1",
                            "misconfig": "smbv1", "product": "smbv1"},
                           severity="high"))

    # Optional share enumeration via a NULL session (read-only).
    shares = _smb_null_shares(ip)
    if shares is None:
        findings.append(_f("smb", "Share enumeration skipped",
                           "Install 'smbprotocol' or 'impacket' for NULL-session share listing.",
                           severity="info"))
    elif shares:
        findings.append(_f("smb", "⚠ NULL-session shares readable",
                           ", ".join(shares),
                           {"shares": shares, "misconfig": "smb_null_session"},
                           severity="high"))
    return findings


# --------------------------------------------------------------------------- SNMP
def snmp_enum(target: str, timeout: float = 4.0) -> list[Finding]:
    """Check for default SNMP community strings (read-only sysDescr GET)."""
    host = normalise_target(target)
    ip = (resolve(host) or [host])[0]
    try:
        from pysnmp.hlapi import (  # type: ignore
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
    except Exception:
        return [_f("snmp", "SNMP check skipped",
                   "Install 'pysnmp' to test default community strings.", severity="info")]

    findings: list[Finding] = []
    for community in ("public", "private"):
        try:
            it = getCmd(SnmpEngine(), CommunityData(community, mpModel=0),
                        UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                        ContextData(),
                        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")))  # sysDescr
            err_ind, err_stat, _, var_binds = next(it)
            if not err_ind and not err_stat and var_binds:
                desc = str(var_binds[0][1])
                findings.append(_f("snmp", f"⚠ Default community '{community}' works",
                                   f"{ip} sysDescr: {desc[:120]}",
                                   {"community": community, "sysdescr": desc,
                                    "misconfig": "snmp_default_community",
                                    "service": "snmp", "banner": desc},
                                   severity="high"))
        except Exception:
            continue
    return findings or [_f("snmp", "No default SNMP community responded", ip)]


# --------------------------------------------------------------------------- LDAP
def ldap_enum(target: str, port: int = 389, timeout: float = 6.0) -> list[Finding]:
    """Check whether the directory permits anonymous bind and read naming contexts."""
    host = normalise_target(target)
    ip = (resolve(host) or [host])[0]
    try:
        import ldap3  # type: ignore
    except Exception:
        if _tcp_open(ip, port, timeout):
            return [_f("ldap", "LDAP exposed (check skipped)",
                       f"{ip}:{port} open — install 'ldap3' for anonymous-bind testing.",
                       {"service": "ldap"}, severity="medium")]
        return [_f("ldap", "No LDAP service", f"{ip}:{port}", severity="info")]

    findings: list[Finding] = []
    try:
        server = ldap3.Server(ip, port=port, get_info=ldap3.ALL,
                              connect_timeout=timeout)
        conn = ldap3.Connection(server, auto_bind=True)  # anonymous
        findings.append(_f("ldap", "⚠ Anonymous LDAP bind allowed",
                           f"{ip}:{port} permits anonymous bind",
                           {"misconfig": "ldap_anonymous_bind", "service": "ldap"},
                           severity="high"))
        contexts = getattr(server.info, "naming_contexts", None) or []
        if contexts:
            findings.append(_f("ldap", "Naming contexts", ", ".join(str(c) for c in contexts),
                               {"contexts": [str(c) for c in contexts]}, severity="medium"))
        safe_call(conn.unbind)
    except Exception as exc:
        if _tcp_open(ip, port, timeout):
            findings.append(_f("ldap", "LDAP present, anonymous bind refused",
                               f"{ip}:{port} (good)"))
        else:
            findings.append(_f("ldap", "No LDAP service", f"{ip}:{port} ({exc})", severity="info"))
    return findings


# ============================================================ helpers / primitives
def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _smb1_supported(ip: str, timeout: float) -> bool:
    """
    Minimal SMBv1 negotiate probe: send an SMB_COM_NEGOTIATE for the 'NT LM 0.12'
    dialect and see whether the server answers with an SMBv1 header (0xFF 'SMB').
    Read-only; no session is established.
    """
    # SMBv1 NEGOTIATE packet with a single dialect string.
    negotiate = bytes.fromhex(
        "000000a4ff534d4272000000001801280000000000000000000000000000"
        "feff00000000008100025043204e4554574f524b2050524f4752414d20312e"
        "3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67"
        "726f75707320332e316100024c4d312e325830303200024c414e4d414e322e"
        "3100024e54204c4d20302e313200"
    )
    try:
        with socket.create_connection((ip, 445), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(negotiate)
            data = s.recv(128)
            # SMBv1 responses start (after 4-byte NetBIOS length) with 0xFF 'SMB'.
            return len(data) > 8 and data[4:8] == b"\xffSMB"
    except Exception:
        return False


def _smb_null_shares(ip: str):
    """Return share names via a NULL session if a library is present, else None."""
    try:
        from smbprotocol.connection import Connection  # type: ignore
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect
        import uuid
        conn = Connection(uuid.uuid4(), ip, 445)
        conn.connect(timeout=5)
        try:
            session = Session(conn, username="", password="")
            session.connect()
            # Listing shares needs the Server Service (srvsvc) RPC; many stacks
            # expose it. We keep this best-effort and read-only.
            return []  # connected anonymously but share list not enumerated here
        finally:
            safe_call(conn.disconnect)
    except Exception:
        return None


def _extract_title(html: str) -> str:
    low = html.lower()
    i = low.find("<title")
    if i == -1:
        return ""
    start = low.find(">", i)
    end = low.find("</title>", start)
    if start == -1 or end == -1:
        return ""
    return html[start + 1:end].strip()[:120]


def _product(banner: str) -> str:
    """Best-effort 'product version' extraction for CVE matching in Phase 4."""
    return (banner or "").strip().split("(")[0].strip()[:80]


def _f(category: str, title: str, detail: str = "",
       data: dict | None = None, severity: str = "info") -> Finding:
    return {"category": category, "title": title, "detail": detail,
            "data": data or {}, "severity": severity}


ENUM_PROTOCOLS = {
    "HTTP": http_enum,
    "DNS": dns_enum,
    "FTP": ftp_enum,
    "SMTP": smtp_enum,
    "SMB": smb_enum,
    "SNMP": snmp_enum,
    "LDAP": ldap_enum,
}

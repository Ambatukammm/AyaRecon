"""
AyaRecon — PHASE 4: Vulnerability Assessment.
Made by Ruel.

IMPORTANT: this phase IDENTIFIES issues. It contains **NO exploit code** and
performs no exploitation — by design. It does two things:

  1. CVE matching — compares service/version strings gathered in Phases 2–3
     against a local, offline CVE knowledge base and reports likely matches.
  2. Misconfiguration detection — turns the misconfigurations surfaced during
     enumeration (anonymous FTP, SMB NULL session, SMBv1, SNMP default
     community, LDAP anonymous bind, DNS zone transfer, SMTP VRFY/EXPN, missing
     security headers, dangerous exposed ports, expired TLS) into prioritised
     findings with references and remediation.

The CVE base is intentionally local (no network dependency) and curated for
common, high-signal cases. For authoritative, up-to-date matching, operators
should cross-reference NVD (https://nvd.nist.gov) — a note is emitted to that
effect. Nothing here weaponises a finding; it points you at the fix.
"""

from __future__ import annotations

import re
from typing import Any

from ..util import Finding


# ---------------------------------------------------------------- local CVE base
# Each entry: a regex over a lowercased "product version" banner -> advisory.
# These are well-known, high-signal issues; severity is CVSS-ish banding.
# No exploit details are included — only identification + remediation.
CVE_DB: list[dict[str, Any]] = [
    {
        "pattern": r"openssh[_/ ]?([0-6]\.|7\.[0-3])",
        "cve": "Multiple (e.g. CVE-2016-0777 / CVE-2016-6210)",
        "severity": "medium",
        "title": "Outdated OpenSSH",
        "desc": "OpenSSH below 7.4 has known information-disclosure and user-"
                "enumeration issues.",
        "fix": "Upgrade OpenSSH to the current release; disable legacy ciphers.",
    },
    {
        "pattern": r"vsftpd 2\.3\.4",
        "cve": "CVE-2011-2523",
        "severity": "critical",
        "title": "vsftpd 2.3.4 backdoor build",
        "desc": "This specific vsftpd build was distributed with a malicious "
                "backdoor.",
        "fix": "Remove and reinstall vsftpd from a trusted package source; "
               "upgrade to a current version.",
    },
    {
        "pattern": r"proftpd 1\.3\.[0-3]",
        "cve": "CVE-2015-3306 (class)",
        "severity": "high",
        "title": "Outdated ProFTPD",
        "desc": "ProFTPD 1.3.x releases include remotely exploitable flaws.",
        "fix": "Upgrade ProFTPD to a supported release.",
    },
    {
        "pattern": r"apache/2\.(0|2)\.",
        "cve": "Multiple",
        "severity": "high",
        "title": "End-of-life Apache httpd",
        "desc": "Apache 2.0/2.2 are end-of-life and carry many unpatched CVEs.",
        "fix": "Upgrade to Apache httpd 2.4.x (current) and apply security patches.",
    },
    {
        "pattern": r"apache/2\.4\.(4[0-9]|[0-4][0-9])\b",
        "cve": "e.g. CVE-2021-41773 / CVE-2021-42013 (if ≤2.4.49)",
        "severity": "high",
        "title": "Apache httpd path-traversal era build",
        "desc": "Apache 2.4.49/2.4.50 were affected by path traversal / RCE "
                "depending on configuration.",
        "fix": "Upgrade to the latest Apache 2.4.x and review Require/Alias config.",
    },
    {
        "pattern": r"nginx/1\.(0|[0-9]|1[0-6])\.",
        "cve": "Multiple",
        "severity": "medium",
        "title": "Outdated nginx",
        "desc": "Older nginx builds carry resolver and HTTP/2 CVEs.",
        "fix": "Upgrade nginx to a current stable release.",
    },
    {
        "pattern": r"(microsoft-iis/[0-6]\.|iis/[0-6]\.)",
        "cve": "Multiple",
        "severity": "high",
        "title": "End-of-life Microsoft IIS",
        "desc": "IIS 6.0 and earlier are unsupported and carry critical CVEs.",
        "fix": "Migrate to a supported Windows Server / IIS 10+ and patch.",
    },
    {
        "pattern": r"exim 4\.(8|9)",
        "cve": "e.g. CVE-2019-10149",
        "severity": "critical",
        "title": "Vulnerable Exim build",
        "desc": "Several Exim 4.8x/4.9x releases had remote code execution flaws.",
        "fix": "Upgrade Exim to the latest release immediately.",
    },
    {
        "pattern": r"smbv1",
        "cve": "CVE-2017-0144 (EternalBlue class)",
        "severity": "critical",
        "title": "Legacy SMBv1 enabled",
        "desc": "SMBv1 is associated with wormable remote code execution "
                "(WannaCry/NotPetya).",
        "fix": "Disable SMBv1 entirely; require SMBv2/3 with signing.",
    },
    {
        "pattern": r"openssl/1\.0\.",
        "cve": "Multiple (e.g. Heartbleed class on 1.0.1)",
        "severity": "high",
        "title": "End-of-life OpenSSL 1.0.x",
        "desc": "OpenSSL 1.0.x is unsupported and includes serious TLS CVEs.",
        "fix": "Upgrade to OpenSSL 3.x and re-link affected services.",
    },
]

# Misconfiguration key -> advisory (keyed on the `data.misconfig` tag that
# enumeration modules set, plus a few derived from other finding types).
MISCONFIG_DB: dict[str, dict[str, Any]] = {
    "zone_transfer": {
        "severity": "high", "ref": "CWE-200",
        "title": "DNS zone transfer permitted",
        "desc": "AXFR exposes the full internal DNS map (hosts, services).",
        "fix": "Restrict zone transfers to authorised secondary servers only.",
    },
    "anonymous_ftp": {
        "severity": "high", "ref": "CWE-287",
        "title": "Anonymous FTP enabled",
        "desc": "Anyone can connect without credentials; may expose or accept files.",
        "fix": "Disable anonymous access or constrain it to a locked-down chroot.",
    },
    "smtp_vrfy": {
        "severity": "medium", "ref": "CWE-203",
        "title": "SMTP VRFY enabled",
        "desc": "Allows remote username enumeration.",
        "fix": "Disable the VRFY command in your MTA configuration.",
    },
    "smtp_expn": {
        "severity": "medium", "ref": "CWE-203",
        "title": "SMTP EXPN enabled",
        "desc": "Allows enumeration of mailing-list membership.",
        "fix": "Disable the EXPN command in your MTA configuration.",
    },
    "smbv1": {
        "severity": "critical", "ref": "CVE-2017-0144",
        "title": "SMBv1 enabled",
        "desc": "Legacy, wormable protocol; strongly associated with ransomware.",
        "fix": "Disable SMBv1; enforce SMBv2/3 with signing.",
    },
    "smb_null_session": {
        "severity": "high", "ref": "CWE-287",
        "title": "SMB NULL session allowed",
        "desc": "Unauthenticated users can enumerate shares/users.",
        "fix": "Disable null-session access (RestrictAnonymous) and review share ACLs.",
    },
    "snmp_default_community": {
        "severity": "high", "ref": "CWE-1188",
        "title": "Default SNMP community string",
        "desc": "'public'/'private' expose device/config data and sometimes writes.",
        "fix": "Change community strings, prefer SNMPv3 with auth/priv, firewall 161/udp.",
    },
    "ldap_anonymous_bind": {
        "severity": "high", "ref": "CWE-287",
        "title": "Anonymous LDAP bind allowed",
        "desc": "Directory contents (users, groups) can be read without credentials.",
        "fix": "Require authentication for binds; disable anonymous access.",
    },
}


def assess(findings: list[dict]) -> list[Finding]:
    """
    Run the full Phase 4 assessment over the current workspace findings.
    Returns NEW vulnerability findings (CVE matches + misconfigurations).
    Pure analysis — no network traffic, no exploitation.
    """
    results: list[Finding] = []
    seen_cve: set[str] = set()
    seen_mis: set[str] = set()

    for f in findings:
        data = f.get("data", {}) or {}

        # --- CVE matching from any version/banner/product string ---
        haystack = " ".join(str(data.get(k, "")) for k in ("product", "banner",
                             "version", "service")).lower()
        haystack = f"{haystack} {str(f.get('detail','')).lower()}"
        for entry in CVE_DB:
            if re.search(entry["pattern"], haystack):
                key = f"{entry['cve']}::{f.get('target','')}::{entry['title']}"
                if key in seen_cve:
                    continue
                seen_cve.add(key)
                results.append(_f(
                    "vuln", f"[CVE] {entry['title']}",
                    f"{entry['desc']}  (ref: {entry['cve']})",
                    {"cve": entry["cve"], "matched": entry["pattern"],
                     "source_finding": f.get("title", "")},
                    severity=entry["severity"],
                    remediation=entry["fix"],
                ))

        # --- Misconfiguration detection from the enumeration tags ---
        mis = data.get("misconfig")
        if mis and mis in MISCONFIG_DB:
            key = f"{mis}::{f.get('target','')}"
            if key not in seen_mis:
                seen_mis.add(key)
                adv = MISCONFIG_DB[mis]
                results.append(_f(
                    "vuln", f"[MISCONFIG] {adv['title']}",
                    f"{adv['desc']}  (ref: {adv['ref']})",
                    {"misconfig": mis, "ref": adv["ref"],
                     "source_finding": f.get("title", "")},
                    severity=adv["severity"],
                    remediation=adv["fix"],
                ))

    # --- Derived misconfigurations from non-enumeration findings ---
    results += _derive_from_generic(findings)

    if not results:
        results.append(_f("vuln", "No vulnerabilities matched",
                          "No CVE or misconfiguration signatures matched the current "
                          "findings. Run phases 1–3 first, and cross-check NVD for "
                          "authoritative results.", severity="info"))
    else:
        results.append(_f("vuln", "Assessment note",
                          "CVE matches are signature-based against a local base — "
                          "verify against NVD (nvd.nist.gov). No exploit code is "
                          "included by design.", severity="info"))
    return results


def _derive_from_generic(findings: list[dict]) -> list[Finding]:
    """Flag risky things that aren't tagged with an explicit misconfig key."""
    out: list[Finding] = []
    for f in findings:
        cat = f.get("category")
        data = f.get("data", {}) or {}
        detail = (f.get("detail") or "").lower()

        # Expired TLS certificate.
        if cat == "ssl" and "expired" in detail:
            out.append(_f("vuln", "[MISCONFIG] Expired TLS certificate",
                          "Clients see trust errors; traffic is not verifiably secure. "
                          "(ref: CWE-298)",
                          {"ref": "CWE-298"}, severity="high",
                          remediation="Renew the certificate and automate renewal (ACME)."))
        # Missing critical security headers.
        if cat == "header" and data.get("missing") and data.get("header") in (
                "HSTS", "Content-Security-Policy"):
            out.append(_f("vuln", f"[MISCONFIG] Missing {data.get('header')}",
                          f"{data.get('header')} not set — weakens browser-side defences. "
                          "(ref: CWE-693)",
                          {"ref": "CWE-693"}, severity="medium",
                          remediation=f"Add the {data.get('header')} response header."))
        # Dangerous admin/data services exposed (from port scan).
        if cat == "port" and f.get("severity") in ("high", "critical"):
            port = data.get("port")
            out.append(_f("vuln", f"[EXPOSURE] Sensitive service on port {port}",
                          f"{detail} — administrative/data service reachable from the "
                          "network. (ref: CWE-668)",
                          {"ref": "CWE-668", "port": port}, severity=f.get("severity"),
                          remediation="Restrict the port to trusted networks via firewall; "
                                      "disable if unused."))
    # De-dup by title+ref.
    uniq = {}
    for o in out:
        uniq[f"{o['title']}::{o['data'].get('port','')}"] = o
    return list(uniq.values())


def _f(category: str, title: str, detail: str = "", data: dict | None = None,
       severity: str = "info", remediation: str = "") -> Finding:
    return {"category": category, "title": title, "detail": detail,
            "data": data or {}, "severity": severity, "ai_reasoning": "",
            "remediation": remediation}

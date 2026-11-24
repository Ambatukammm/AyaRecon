"""
AyaRecon — PART 4: Defensive mode (protect yourself).
Made by Ruel.

Defensive mode runs the same checks AyaRecon uses offensively, but pointed at the
user's OWN assets, and rolls the results into:

  • an exposure summary (what an attacker sees),
  • a security grade (A–F) with a per-category breakdown,
  • change detection vs the previous self-scan.

It reuses passive + active modules rather than duplicating logic.
"""

from __future__ import annotations

from typing import Any

from ..util import Finding, normalise_target
from . import passive, active

# Weighting for the grade: how much each severity costs.
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}


def self_audit(target: str, confirm_owned: bool = True,
               include_active: bool = True) -> list[Finding]:
    """
    Run a bundle of checks against the user's own asset. The permission layer
    must already have confirmed ownership before this is called.
    """
    host = normalise_target(target)
    findings: list[Finding] = []

    # Passive — always safe.
    findings += passive.dns_records(host)
    findings += passive.whois_lookup(host)
    findings += passive.ssl_certificate(host)
    findings += passive.subdomains_crtsh(host)

    # Active — against your own box this is the point of a self-audit.
    if include_active:
        findings += active.ping_host(host)
        open_ports = []
        port_findings = active.port_scan(host)
        for f in port_findings:
            if f["category"] == "port" and f.get("data", {}).get("port"):
                open_ports.append(f["data"]["port"])
        findings += port_findings
        findings += active.http_fingerprint(host)
        if open_ports:
            findings += active.service_versions(host, open_ports[:15])

    return findings


def grade(severity_counts: dict[str, int]) -> dict[str, Any]:
    """Turn severity counts into a 0–100 score and a letter grade."""
    penalty = sum(SEVERITY_WEIGHT.get(sev, 0) * n for sev, n in severity_counts.items())
    score = max(0, 100 - penalty)
    if score >= 90:
        letter = "A"
    elif score >= 75:
        letter = "B"
    elif score >= 60:
        letter = "C"
    elif score >= 45:
        letter = "D"
    elif score >= 25:
        letter = "E"
    else:
        letter = "F"
    return {"score": score, "grade": letter, "penalty": penalty,
            "counts": dict(severity_counts)}


def diff_scans(previous: list[dict], current: list[dict]) -> dict[str, list[str]]:
    """
    Compare two sets of findings (lists of finding dicts) and report what is
    newly exposed vs resolved. Keyed on category+detail for stability.
    """
    def key(f: dict) -> str:
        return f"{f.get('category')}::{f.get('title')}::{f.get('detail')}"

    prev_keys = {key(f) for f in previous}
    cur_keys = {key(f) for f in current}
    new = [f["detail"] for f in current if key(f) not in prev_keys]
    resolved = [f["detail"] for f in previous if key(f) not in cur_keys]
    return {"new_exposure": new, "resolved": resolved}


def privacy_footprint(domain: str, emails: list[str] | None = None,
                      hibp_key: str = "") -> list[Finding]:
    """What personal/public data is visible: subdomains, archives, breaches."""
    host = normalise_target(domain)
    findings: list[Finding] = []
    findings += passive.subdomains_crtsh(host)
    findings += passive.wayback_snapshots(host, limit=15)
    for email in (emails or []):
        findings += passive.breach_lookup(email, api_key=hibp_key)
    return findings

"""
AyaRecon — Nmap integration.
Made by Ruel.

Drives the real nmap binary and parses its XML output (-oX) into AyaRecon
finding dicts, so nmap results land in the same workspace database and flow into
Phase 4 (CVE matching reads the service/version strings nmap reports).

AyaRecon does not reimplement nmap — it orchestrates it. If nmap isn't
installed, every function returns a single informational finding with the
install hint instead of failing.

Only non-intrusive, standard scan presets are exposed here. Raw custom flags are
allowed (power users expect that), but AyaRecon strips a few obviously dangerous
ones and records the exact command in the permission audit log via the scanner.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from ..util import Finding, normalise_target

# Scan presets -> nmap arguments (XML output is added automatically).
PRESETS = {
    "Quick (top 100 TCP)": ["-T4", "-F"],
    "Standard (top 1000 + versions)": ["-T4", "-sV"],
    "Service + default scripts": ["-T4", "-sV", "-sC"],
    "Full TCP + versions": ["-T4", "-p-", "-sV"],
    "OS + service detection": ["-T4", "-O", "-sV"],
    "UDP top ports": ["-T4", "-sU", "--top-ports", "50"],
    "Ping sweep (discovery)": ["-sn"],
}

# Flags we refuse to pass through from a custom string (keep it recon, not attack).
_BLOCKED_FLAGS = {"--script=exploit", "--script", "-oG"}  # --script handled below


def available() -> bool:
    return shutil.which("nmap") is not None


def run(target: str, args: list[str] | None = None,
        preset: str | None = None, timeout: int = 1200) -> tuple[list[Finding], str]:
    """
    Run nmap against target. Returns (findings, raw_command).
    `preset` (a key of PRESETS) takes precedence; otherwise `args` is used.
    """
    host = normalise_target(target)
    if not available():
        return ([_f("nmap", "Nmap not installed",
                    "Install nmap to enable scanning — see the Tools tab.",
                    severity="info")], "")

    scan_args = PRESETS.get(preset or "", None)
    if scan_args is None:
        scan_args = _sanitise(args or ["-T4", "-F"])

    with tempfile.TemporaryDirectory() as tmp:
        xml_path = Path(tmp) / "scan.xml"
        cmd = ["nmap", *scan_args, "-oX", str(xml_path), host]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return ([_f("nmap", "Nmap timed out", f"{host} ({timeout}s)", severity="low")],
                    " ".join(cmd))
        except Exception as exc:
            return ([_f("nmap", "Nmap failed", str(exc), severity="low")], " ".join(cmd))

        if not xml_path.exists():
            return ([_f("nmap", "Nmap produced no output", host, severity="low")],
                    " ".join(cmd))
        findings = _parse_xml(xml_path.read_text(encoding="utf-8", errors="ignore"), host)
        return findings, " ".join(cmd)


def _sanitise(args: list[str]) -> list[str]:
    """Drop obviously exploit-oriented flags from a custom argument list."""
    out = []
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        low = a.lower()
        if low in ("-og",):
            continue
        # Block NSE 'exploit'/'brute'/'vuln-exploit' script categories.
        if low.startswith("--script"):
            val = a.split("=", 1)[1] if "=" in a else ""
            if any(bad in val.lower() for bad in ("exploit", "brute", "dos", "malware")):
                continue
            if "=" not in a:
                skip_next = True  # also skip the following value token
                continue
        out.append(a)
    return out or ["-T4", "-F"]


def _parse_xml(xml_text: str, host: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return [_f("nmap", "Could not parse nmap XML", host, severity="low")]

    for hostnode in root.findall("host"):
        addr_el = hostnode.find("address")
        addr = addr_el.get("addr") if addr_el is not None else host

        # OS guesses
        os_el = hostnode.find("os")
        if os_el is not None:
            for match in os_el.findall("osmatch")[:1]:
                findings.append(_f("nmap", "OS guess",
                                   f"{addr}: {match.get('name')} "
                                   f"({match.get('accuracy')}% accuracy)",
                                   {"os": match.get("name")}))

        ports_el = hostnode.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port.get("portid")
            proto = port.get("protocol")
            svc = port.find("service")
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            banner = " ".join(x for x in (product, version) if x).strip()

            sev = "info"
            if int(portid) in (3389, 23, 445, 139, 135, 5900, 6379, 27017,
                               9200, 1433, 3306, 5432):
                sev = "high"
            detail = f"{addr} {portid}/{proto} open — {name}"
            if banner:
                detail += f" ({banner})"
            findings.append(_f("nmap", f"Open port {portid}/{proto}", detail,
                               {"port": int(portid), "protocol": proto,
                                "service": name, "product": banner,
                                "banner": banner, "ip": addr},
                               severity=sev))
    if not findings:
        findings.append(_f("nmap", "No open ports reported", host))
    return findings


def _f(category, title, detail="", data=None, severity="info") -> Finding:
    return {"category": category, "title": title, "detail": detail,
            "data": data or {}, "severity": severity}

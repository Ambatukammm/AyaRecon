"""
AyaRecon — minimal CLI (headless fallback / scripting).
Made by Ruel.

Passive checks run freely. Active and enumeration require the same confirmation
and gate as the GUI — here via explicit flags so nothing runs by accident.
"""

from __future__ import annotations

import sys

from . import __app_name__, __author__, __version__
from .config import Config, DEFAULT_DB_PATH
from .db import Database
from .permissions import PermissionManager, PERMISSION_PHRASE
from .ai.engine import AIEngine
from .scanner import Scanner

PASSIVE = {
    "dns": "passive.dns", "whois": "passive.whois", "ssl": "passive.ssl",
    "subdomains": "passive.subdomains", "wayback": "passive.wayback",
    "all": "passive.all",
}
ACTIVE = {"ping": "active.ping", "ports": "active.portscan", "http": "active.http"}
# Phase 3 per-protocol enumeration (direct contact → treated as active/confirm).
ENUM_SVC = {
    "http-enum": "enumeration.http", "dns-enum": "enumeration.dns",
    "ftp-enum": "enumeration.ftp", "smtp-enum": "enumeration.smtp",
    "smb-enum": "enumeration.smb", "snmp-enum": "enumeration.snmp",
    "ldap-enum": "enumeration.ldap", "enum-all": "enumeration.all",
}
# Phase 4 analysis (no network).
VULN = {"vuln": "vuln.assess"}
# Gated wordlist discovery.
ENUM = {"dirs": "enum.directories", "subs": "enum.subdomains"}


def _print_findings(findings):
    if not findings:
        print("  (no findings)")
        return
    for f in findings:
        sev = f.get("severity", "info").upper()
        print(f"  [{sev:<8}] {f.get('title')}: {f.get('detail')}")
        if f.get("remediation"):
            print(f"             fix: {f['remediation']}")


def main(argv: list[str]) -> int:
    print(f"{__app_name__} v{__version__} — made by {__author__}")
    config = Config()
    db = Database(DEFAULT_DB_PATH)
    perms = PermissionManager(config, db)
    ai = AIEngine(config)
    scanner = Scanner(config, db, perms, ai)
    ws = db.create_workspace("cli")

    if len(argv) >= 2:
        cmd, target = argv[0], argv[1]
        return _one_shot(scanner, perms, ws, cmd, target, argv[2:])

    # interactive
    print("Phase 1  dns/whois/ssl/subdomains/wayback/all <target>")
    print("Phase 2  ping/ports/http <target>                 (active — asks to confirm)")
    print("Phase 3  http-enum/dns-enum/ftp-enum/smtp-enum/smb-enum/snmp-enum/ldap-enum/enum-all <target>")
    print("Phase 4  vuln <target>                            (analysis of findings so far)")
    print("Gated    dirs/subs <target>                       (needs gate + permission)")
    print("         quit")
    while True:
        try:
            line = input("netreconai> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in ("quit", "exit"):
            break
        parts = line.split()
        if len(parts) < 2:
            print("  usage: <command> <target>")
            continue
        _one_shot(scanner, perms, ws, parts[0], parts[1], parts[2:])
    db.close()
    return 0


def _one_shot(scanner, perms, ws, cmd, target, extra) -> int:
    if cmd in PASSIVE:
        _, findings = scanner.run(ws, target, "passive", PASSIVE[cmd], confirmed=True)
        _print_findings(findings)
    elif cmd in ACTIVE:
        ok = input(f"  Active scan of {target} — do you have authorisation? [y/N] ")
        if ok.lower() != "y":
            print("  aborted.")
            return 0
        _, findings = scanner.run(ws, target, "active", ACTIVE[cmd],
                                  confirmed=True, confirmation_text="cli y")
        _print_findings(findings)
    elif cmd in ENUM_SVC:
        ok = input(f"  Service enumeration of {target} makes direct contact — "
                   "authorised? [y/N] ")
        if ok.lower() != "y":
            print("  aborted.")
            return 0
        _, findings = scanner.run(ws, target, "active", ENUM_SVC[cmd],
                                  confirmed=True, confirmation_text="cli y")
        _print_findings(findings)
    elif cmd in VULN:
        _, findings = scanner.run(ws, target, "passive", VULN[cmd])
        _print_findings(findings)
    elif cmd in ENUM:
        if not perms.enumeration_unlocked:
            phrase = input(f'  Type "{PERMISSION_PHRASE}" to unlock enumeration: ')
            if not perms.unlock_enumeration(phrase):
                print("  not unlocked.")
                return 0
        ok = input(f"  WRITTEN PERMISSION to enumerate {target}? [y/N] ")
        if ok.lower() != "y":
            print("  aborted.")
            return 0
        dec, findings = scanner.run(ws, target, "enumeration", ENUM[cmd],
                                    confirmed=True, confirmation_text="cli y")
        if not dec.allowed:
            print("  blocked:", dec.reason)
        _print_findings(findings)
    else:
        print(f"  unknown command: {cmd}")
    return 0

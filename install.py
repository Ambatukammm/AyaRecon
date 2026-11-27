#!/usr/bin/env python3
"""
AyaRecon — one-shot setup / bootstrap.
Made by Ruel.

Policy: AUTO-INSTALL the Python libraries (safe, via pip), then DETECT the
external system tools (nmap, Wireshark/tshark, etc.) and GUIDE you to install
whatever is missing with the exact command for your platform. AyaRecon does not
silently install system software or drivers — those ship their own signed
installers and licences.

Usage:
    python install.py            # DEFAULT: pip deps + auto-install every missing tool
    python install.py --no-auto  # pip deps + report, but don't auto-install tools
    python install.py --report   # only detect/report tools (no changes)
    python install.py --pip      # only pip-install the Python deps

On Windows, auto-install uses winget and Chocolatey (it will install Chocolatey
for you if needed) — run this from an **Administrator** terminal so those can
install system software without prompting repeatedly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REQ = HERE / "requirements.txt"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[90m", "\033[0m"


def pip_install() -> bool:
    if not REQ.exists():
        print(f"{YELLOW}requirements.txt not found — skipping pip step.{RESET}")
        return False
    print(f"{DIM}Installing Python dependencies (pip)…{RESET}")
    cmds = [
        [sys.executable, "-m", "pip", "install", "-r", str(REQ)],
        # PEP-668 managed environments (e.g. some Linux) need this flag.
        [sys.executable, "-m", "pip", "install", "--break-system-packages",
         "-r", str(REQ)],
    ]
    for cmd in cmds:
        try:
            res = subprocess.run(cmd)
            if res.returncode == 0:
                print(f"{GREEN}Python dependencies installed.{RESET}")
                return True
        except Exception as exc:
            print(f"{YELLOW}pip attempt failed: {exc}{RESET}")
    print(f"{YELLOW}Could not install all Python deps automatically. "
          f"AyaRecon still runs — missing libs degrade gracefully.{RESET}")
    return False


def tool_report() -> None:
    # Imported here so the script works even before deps are installed.
    sys.path.insert(0, str(HERE))
    from ayarecon.integrations import tools

    os_name = tools.current_os()
    rows = tools.detect_all()
    installed = [r for r in rows if r["installed"]]
    missing = [r for r in rows if not r["installed"]]

    print()
    print("=" * 66)
    print(f"  AyaRecon external-tool report  ·  platform: {os_name}  ·  by Ruel")
    print("=" * 66)

    print(f"\n{GREEN}Installed ({len(installed)}):{RESET}")
    for r in installed:
        ver = f" — {r['version']}" if r["version"] else ""
        print(f"  {GREEN}✓{RESET} {r['name']:<16} [{r['category']}]{DIM}{ver}{RESET}")

    required_missing = [r for r in missing if not r.get("optional")]
    optional_missing = [r for r in missing if r.get("optional")]

    if required_missing:
        print(f"\n{RED}Missing ({len(required_missing)}):{RESET}")
        for r in required_missing:
            print(f"  {RED}✗{RESET} {r['name']:<16} [{r['category']}]  {r['purpose']}")
            print(f"      {YELLOW}install:{RESET} {r['hint']}")
            if r["optional_pip"]:
                print(f"      {DIM}python integration: pip install {r['optional_pip']}{RESET}")

    if optional_missing:
        print(f"\n{DIM}Optional (not needed for the core workflow):{RESET}")
        for r in optional_missing:
            print(f"  ○ {r['name']:<16} [{r['category']}]  {r['purpose']}")
            print(f"      {DIM}{r['hint']}{RESET}")

    print(f"\n{DIM}AyaRecon runs now regardless. Live packet capture also needs "
          f"admin/root (and Npcap on Windows).{RESET}\n")


def auto_install_tools() -> None:
    sys.path.insert(0, str(HERE))
    from ayarecon.integrations import tools

    missing = tools.missing_tools()
    # Only auto-install required tools; optional ones (masscan/dig/nikto on
    # Windows) are left for the user to add deliberately.
    auto = [r for r in missing if r.get("can_auto") and not r.get("optional")]
    if not auto:
        print(f"{YELLOW}Nothing to auto-install (or no package manager available). "
              f"See the guide above.{RESET}")
        return
    print(f"\n{DIM}Auto-installing {len(auto)} tool(s) via your package manager "
          f"(you may see UAC/sudo prompts)…{RESET}")
    for r in auto:
        print(f"\n--- {r['name']} ---")
        tools.install_tool(r["key"], on_line=print)


def main(argv: list[str]) -> int:
    print(f"AyaRecon setup — made by Ruel\n")
    report_only = "--check" in argv or "--report" in argv
    only_pip = "--pip" in argv
    no_auto = "--no-auto" in argv

    if report_only:
        tool_report()
        print("\nReport only. Run 'python install.py' to install everything.")
        return 0

    # Default: install the Python libraries, show the report, then auto-install
    # every missing external tool we can.
    pip_install()
    if only_pip:
        print("\nDone (pip only). Launch AyaRecon with:  python main.py")
        return 0
    try:
        tool_report()
    except Exception as exc:
        print(f"{YELLOW}Tool detection skipped: {exc}{RESET}")
    if not no_auto:
        try:
            auto_install_tools()
            print(f"\n{DIM}Re-checking…{RESET}")
            tool_report()
        except Exception as exc:
            print(f"{YELLOW}Auto-install skipped: {exc}{RESET}")

    print("\nDone. Launch AyaRecon with:  python main.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

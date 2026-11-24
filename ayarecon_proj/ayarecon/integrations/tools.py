"""
AyaRecon — external tool registry & detection.
Made by Ruel.

A single, data-driven catalogue of the external tools AyaRecon can drive. The
GUI "Tools" tab and the installer both read this registry, so adding a new tool
is a one-entry change here.

Detection is read-only (we just look for the binary on PATH / ask its version).
Install hints are per-platform and point at official sources; AyaRecon follows a
"detect and guide" policy — it tells the user the exact command to run rather
than silently installing system software.
"""

from __future__ import annotations

import os as _os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional


def current_os() -> str:
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "macos"
    return "linux"


@dataclass
class Tool:
    key: str
    name: str
    category: str
    binary: str                     # executable to look for on PATH
    purpose: str
    version_args: list[str] = field(default_factory=lambda: ["--version"])
    # install command per platform (shown to the user, not auto-run by default)
    install: dict[str, str] = field(default_factory=dict)
    homepage: str = ""
    optional_pip: str = ""          # python package that enables deeper integration
    # Known install locations to check when the tool isn't on PATH (mainly
    # Windows GUI apps that don't register a PATH entry). Env vars are expanded.
    probe_paths: list[str] = field(default_factory=list)
    optional: bool = False          # not required for AyaRecon's core workflow

    def path(self) -> Optional[str]:
        p = shutil.which(self.binary)
        if p:
            return p
        for cand in self.probe_paths:
            cand = _os.path.expandvars(cand)
            if _os.path.exists(cand):
                # Put the containing dir on PATH so dependent tools (pyshark→tshark)
                # and version checks can find it this session.
                d = cand if _os.path.isdir(cand) else _os.path.dirname(cand)
                if d and d not in _os.environ.get("PATH", ""):
                    _os.environ["PATH"] = d + _os.pathsep + _os.environ.get("PATH", "")
                return cand
        return None

    def installed(self) -> bool:
        return self.path() is not None

    def version(self) -> str:
        if not self.installed() or not self.version_args:
            return ""
        try:
            out = subprocess.run([self.binary, *self.version_args],
                                 capture_output=True, text=True, timeout=6)
            text = (out.stdout or out.stderr or "").strip()
            return text.splitlines()[0] if text else ""
        except Exception:
            return ""

    def install_hint(self, os_name: str | None = None) -> str:
        os_name = os_name or current_os()
        return self.install.get(os_name, self.homepage or "See the tool's website.")


# -------------------------------------------------------------------- the catalogue
REGISTRY: list[Tool] = [
    Tool("nmap", "Nmap", "Scanning", "nmap",
         "Port scanning, service/version & OS detection, NSE scripts.",
         install={
             "windows": "winget install Insecure.Nmap",
             "macos": "brew install nmap",
             "linux": "sudo apt install nmap   (or: sudo dnf install nmap)",
         }, homepage="https://nmap.org/download.html",
         optional_pip="python-nmap"),
    Tool("masscan", "Masscan", "Scanning", "masscan",
         "Very fast internet-scale TCP port scanner. (Optional — nmap covers scanning.)",
         install={
             "windows": "No clean prebuilt Windows binary — use WSL, or skip "
                        "(nmap covers scanning). choco install masscan may work.",
             "macos": "brew install masscan",
             "linux": "sudo apt install masscan",
         }, homepage="https://github.com/robertdavidgraham/masscan",
         optional=True),
    Tool("wireshark", "Wireshark", "Capture", "wireshark",
         "GUI packet analyser (deep inspection).",
         version_args=["--version"],
         install={
             "windows": "winget install WiresharkFoundation.Wireshark",
             "macos": "brew install --cask wireshark",
             "linux": "sudo apt install wireshark",
         }, homepage="https://www.wireshark.org/download.html",
         probe_paths=[r"%ProgramFiles%\Wireshark\Wireshark.exe",
                      r"%ProgramFiles%\Wireshark\wireshark.exe",
                      r"%ProgramW6432%\Wireshark\Wireshark.exe"]),
    Tool("tshark", "TShark", "Capture", "tshark",
         "Wireshark's CLI engine — powers AyaRecon's in-app live capture.",
         install={
             "windows": "Installed with Wireshark (winget install WiresharkFoundation.Wireshark)",
             "macos": "brew install wireshark",
             "linux": "sudo apt install tshark",
         }, homepage="https://www.wireshark.org/",
         optional_pip="pyshark",
         probe_paths=[r"%ProgramFiles%\Wireshark\tshark.exe",
                      r"%ProgramW6432%\Wireshark\tshark.exe"]),
    Tool("npcap", "Npcap", "Capture", "npcap",
         "Windows packet-capture driver required for live capture.",
         version_args=[],
         install={"windows": "Install from https://npcap.com (bundled with Nmap/Wireshark)"},
         homepage="https://npcap.com",
         probe_paths=[r"%SystemRoot%\System32\Npcap",
                      r"%SystemRoot%\System32\wpcap.dll",
                      r"%SystemRoot%\SysWOW64\Npcap",
                      r"%ProgramFiles%\Npcap"]),
    Tool("whois", "whois", "Recon", "whois",
         "Domain/IP registration lookups.",
         version_args=["--version"],
         install={
             "windows": "winget install Microsoft.Sysinternals.Whois  (or use built-in RDAP)",
             "macos": "built-in",
             "linux": "sudo apt install whois",
         }, homepage="https://www.iana.org/whois"),
    Tool("dig", "dig (bind-utils)", "Recon", "dig",
         "DNS lookups & zone transfers. (Optional — AyaRecon has a built-in DNS module.)",
         version_args=["-v"],
         install={
             "windows": "Optional: AyaRecon's built-in DNS covers this. "
                        "For the real dig, install BIND tools or 'choco install bind-toolsonly'.",
             "macos": "built-in",
             "linux": "sudo apt install dnsutils",
         }, homepage="https://www.isc.org/bind/",
         probe_paths=[r"%ProgramFiles%\ISC BIND 9\bin\dig.exe"],
         optional=True),
    Tool("gobuster", "Gobuster", "Enumeration", "gobuster",
         "Directory/DNS/vhost brute-forcing (wordlist discovery).",
         install={
             "windows": "Download from GitHub releases (OJ/gobuster)",
             "macos": "brew install gobuster",
             "linux": "sudo apt install gobuster",
         }, homepage="https://github.com/OJ/gobuster"),
    Tool("nikto", "Nikto", "Web", "nikto",
         "Web server misconfig scanner. (Optional — needs Perl on Windows.)",
         version_args=["-Version"],
         install={
             "windows": "Optional: needs Perl (Strawberry Perl) + clone sullo/nikto, "
                        "or run it from WSL. AyaRecon's Phase-3 HTTP checks cover the basics.",
             "macos": "brew install nikto",
             "linux": "sudo apt install nikto",
         }, homepage="https://github.com/sullo/nikto",
         optional=True),
    Tool("subfinder", "Subfinder", "Recon", "subfinder",
         "Passive subdomain discovery.",
         install={
             "windows": "Download from GitHub releases (projectdiscovery/subfinder)",
             "macos": "brew install subfinder",
             "linux": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
         }, homepage="https://github.com/projectdiscovery/subfinder"),
    Tool("httpx", "httpx", "Web", "httpx",
         "Fast HTTP probing / tech detection.",
         install={
             "windows": "Download from GitHub releases (projectdiscovery/httpx)",
             "macos": "brew install httpx",
             "linux": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
         }, homepage="https://github.com/projectdiscovery/httpx"),
    Tool("ollama", "Ollama", "AI", "ollama",
         "Local LLM runtime that powers AyaRecon's AI analysis offline.",
         install={
             "windows": "winget install Ollama.Ollama",
             "macos": "brew install ollama",
             "linux": "curl -fsSL https://ollama.com/install.sh | sh",
         }, homepage="https://ollama.com/download"),
]

REGISTRY_BY_KEY = {t.key: t for t in REGISTRY}


def detect_all() -> list[dict]:
    """Return a status row per tool: key, name, category, installed, version, hint."""
    os_name = current_os()
    rows = []
    for t in REGISTRY:
        installed = t.installed()
        rows.append({
            "key": t.key,
            "name": t.name,
            "category": t.category,
            "purpose": t.purpose,
            "installed": installed,
            "version": t.version() if installed else "",
            "path": t.path() or "",
            "hint": "" if installed else t.install_hint(os_name),
            "homepage": t.homepage,
            "optional_pip": t.optional_pip,
            "optional": t.optional,
            "can_auto": (not installed) and can_auto_install(t.key, os_name),
        })
    return rows


def missing_tools() -> list[dict]:
    return [r for r in detect_all() if not r["installed"]]




# ==================================================================== auto-install
# AyaRecon tries hard to install everything automatically:
#   • Windows  — winget where it has the package; otherwise Chocolatey (choco),
#                which it will BOOTSTRAP for you if missing; a few Go tools come
#                straight from their GitHub release.
#   • macOS    — Homebrew (brew).
#   • Linux    — apt-get.
# Anything that still can't be auto-installed (needs manual compilation, etc.)
# falls back to a copyable command + download link.
#
# Tools fetched from GitHub releases land in a local bin dir that AyaRecon adds
# to PATH, so no admin rights are needed for those.

import os as _os
import sys as _sys

try:
    from ..config import APP_DIR as _APP_DIR
    BIN_DIR = _APP_DIR / "bin"
except Exception:  # pragma: no cover
    from pathlib import Path as _P
    BIN_DIR = _P(_os.path.expanduser("~")) / ".ayarecon" / "bin"

BIN_DIR.mkdir(parents=True, exist_ok=True)
# Make locally-downloaded tools discoverable by shutil.which / subprocess.
if str(BIN_DIR) not in _os.environ.get("PATH", ""):
    _os.environ["PATH"] = str(BIN_DIR) + _os.pathsep + _os.environ.get("PATH", "")

try:
    import requests as _requests
except Exception:  # pragma: no cover
    _requests = None


# Per-tool package-manager IDs and GitHub repos.
PKG: dict[str, dict] = {
    "nmap":      {"winget": "Insecure.Nmap", "choco": "nmap", "brew": "nmap", "apt": "nmap"},
    "wireshark": {"winget": "WiresharkFoundation.Wireshark", "choco": "wireshark",
                  "brew_cask": "wireshark", "apt": "wireshark tshark"},
    "tshark":    {"choco": "wireshark", "brew": "wireshark", "apt": "tshark"},
    "npcap":     {"choco": "npcap"},
    "masscan":   {"choco": "masscan", "brew": "masscan", "apt": "masscan"},
    "nikto":     {"choco": "nikto", "brew": "nikto", "apt": "nikto"},
    "gobuster":  {"choco": "gobuster", "brew": "gobuster", "apt": "gobuster",
                  "github": ("OJ/gobuster", "gobuster")},
    "whois":     {"winget": "Microsoft.Sysinternals.Whois", "choco": "sysinternals",
                  "apt": "whois"},
    "dig":       {"choco": "bind-toolsonly", "apt": "dnsutils"},
    "subfinder": {"brew": "subfinder", "github": ("projectdiscovery/subfinder", "subfinder")},
    "httpx":     {"brew": "httpx", "github": ("projectdiscovery/httpx", "httpx")},
    "ollama":    {"winget": "Ollama.Ollama", "choco": "ollama", "brew": "ollama"},
}


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def can_auto_install(key: str, os_name: str | None = None) -> bool:
    os_name = os_name or current_os()
    m = PKG.get(key, {})
    if not m:
        return False
    if os_name == "windows":
        # winget (if the id exists and winget present), choco (bootstrappable),
        # or a GitHub binary → all count as auto-installable.
        if "winget" in m and _has("winget"):
            return True
        if "choco" in m:
            return True   # we can bootstrap choco
        return "github" in m
    if os_name == "macos":
        if ("brew" in m or "brew_cask" in m) and _has("brew"):
            return True
        return "github" in m
    # linux
    if "apt" in m and (_has("apt-get") or _has("apt")):
        return True
    return "github" in m


def _emit(on_line, msg):
    if on_line:
        on_line(msg)


def _run(cmd: list[str], on_line=None) -> int:
    _emit(on_line, "$ " + " ".join(cmd))
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        for line in iter(proc.stdout.readline, ""):
            _emit(on_line, line.rstrip("\n"))
        proc.wait()
        return proc.returncode
    except Exception as exc:
        _emit(on_line, f"error: {exc}")
        return -1


def ensure_choco(on_line=None) -> bool:
    """Install Chocolatey if missing (Windows). Needs an elevated (admin) session."""
    if _has("choco"):
        return True
    _emit(on_line, "Chocolatey not found — bootstrapping it (needs Administrator)…")
    ps = (
        "Set-ExecutionPolicy Bypass -Scope Process -Force; "
        "[System.Net.ServicePointManager]::SecurityProtocol = 3072; "
        "iex ((New-Object System.Net.WebClient).DownloadString("
        "'https://community.chocolatey.org/install.ps1'))"
    )
    _run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], on_line)
    ok = _has("choco")
    if not ok:
        _emit(on_line, "Could not install Chocolatey. Re-run AyaRecon as Administrator, "
                       "or install it from https://chocolatey.org/install")
    return ok


def github_install(key: str, on_line=None) -> int:
    """Download a tool's prebuilt binary from its latest GitHub release into BIN_DIR."""
    import io
    import tarfile
    import zipfile

    if _requests is None:
        _emit(on_line, "The 'requests' library is needed for GitHub downloads — "
                       "click 'Install Python libraries (pip)' first.")
        return -1
    repo, binname = PKG[key]["github"]
    os_name = current_os()
    os_tokens = {"windows": ["windows"], "macos": ["darwin", "macos"],
                 "linux": ["linux"]}[os_name]
    arch_tokens = ["amd64", "x86_64", "x64"]
    _emit(on_line, f"Looking up latest {key} release on GitHub…")
    try:
        rel = _requests.get(f"https://api.github.com/repos/{repo}/releases/latest",
                            timeout=20).json()
    except Exception as exc:
        _emit(on_line, f"GitHub lookup failed: {exc}")
        return -1
    asset = None
    for a in rel.get("assets", []):
        n = a.get("name", "").lower()
        if any(t in n for t in os_tokens) and any(t in n for t in arch_tokens) \
                and (n.endswith(".zip") or n.endswith(".tar.gz")):
            asset = a
            break
    if not asset:
        _emit(on_line, f"No prebuilt {os_name} binary found for {key}; install manually.")
        return -1
    url = asset["browser_download_url"]
    _emit(on_line, f"Downloading {asset['name']}…")
    try:
        data = _requests.get(url, timeout=120).content
    except Exception as exc:
        _emit(on_line, f"Download failed: {exc}")
        return -1
    exe = binname + (".exe" if os_name == "windows" else "")
    try:
        if asset["name"].endswith(".zip"):
            zf = zipfile.ZipFile(io.BytesIO(data))
            member = next((m for m in zf.namelist()
                           if m.lower().endswith(exe.lower())), None)
            if not member:
                _emit(on_line, "Binary not found inside the archive.")
                return -1
            target = BIN_DIR / exe
            target.write_bytes(zf.read(member))
        else:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
            member = next((m for m in tf.getmembers()
                           if m.name.lower().endswith(exe.lower())), None)
            if not member:
                _emit(on_line, "Binary not found inside the archive.")
                return -1
            target = BIN_DIR / exe
            target.write_bytes(tf.extractfile(member).read())
        if os_name != "windows":
            _os.chmod(target, 0o755)
        _emit(on_line, f"{key} installed to {target} ✓")
        return 0
    except Exception as exc:
        _emit(on_line, f"Extraction failed: {exc}")
        return -1


def install_tool(key: str, on_line=None) -> int:
    """
    Install `key` by the best method for this OS, streaming output to on_line.
    Returns 0 on success, non-zero/-1 otherwise. Never raises.
    """
    os_name = current_os()
    m = PKG.get(key, {})
    tool = REGISTRY_BY_KEY.get(key)
    if not m:
        _emit(on_line, f"[{key}] No installer defined. "
                       f"{tool.install_hint(os_name) if tool else ''}")
        return -1

    if os_name == "windows":
        # 1) winget if available and it has the package.
        if "winget" in m and _has("winget"):
            rc = _run(["winget", "install", "-e", "--accept-source-agreements",
                       "--accept-package-agreements", "--id", m["winget"]], on_line)
            if rc == 0:
                _emit(on_line, f"[{key}] installed ✓")
                return 0
            _emit(on_line, f"[{key}] winget didn't succeed — trying Chocolatey…")
        # 2) Chocolatey (bootstrap if needed).
        if "choco" in m:
            if ensure_choco(on_line):
                rc = _run(["choco", "install", "-y", *m["choco"].split()], on_line)
                if rc == 0:
                    _emit(on_line, f"[{key}] installed ✓")
                    return 0
        # 3) GitHub release binary (no admin needed).
        if "github" in m:
            return github_install(key, on_line)
        _emit(on_line, f"[{key}] couldn't auto-install. {tool.install_hint(os_name)}")
        return -1

    if os_name == "macos":
        if "brew_cask" in m and _has("brew"):
            rc = _run(["brew", "install", "--cask", m["brew_cask"]], on_line)
            if rc == 0:
                return 0
        if "brew" in m and _has("brew"):
            rc = _run(["brew", "install", *m["brew"].split()], on_line)
            if rc == 0:
                return 0
        if "github" in m:
            return github_install(key, on_line)
        _emit(on_line, f"[{key}] {tool.install_hint(os_name)}")
        return -1

    # linux
    if "apt" in m and (_has("apt-get") or _has("apt")):
        rc = _run(["sudo", "apt-get", "install", "-y", *m["apt"].split()], on_line)
        if rc == 0:
            return 0
    if "github" in m:
        return github_install(key, on_line)
    _emit(on_line, f"[{key}] {tool.install_hint(os_name)}")
    return -1


def pip_install_requirements(on_line=None) -> int:
    """pip-install the bundled requirements.txt, streaming output. Returns exit code."""
    from pathlib import Path
    req = Path(__file__).resolve().parents[2] / "requirements.txt"
    if not req.exists():
        _emit(on_line, "requirements.txt not found.")
        return -1
    for extra in ([], ["--break-system-packages"]):
        rc = _run([_sys.executable, "-m", "pip", "install", *extra, "-r", str(req)], on_line)
        if rc == 0:
            _emit(on_line, "Python libraries installed ✓")
            return 0
    _emit(on_line, "pip install did not complete cleanly (AyaRecon still runs).")
    return -1

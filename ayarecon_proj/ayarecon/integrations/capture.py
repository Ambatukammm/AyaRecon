"""
AyaRecon — packet capture & analysis (Wireshark-style).
Made by Ruel.

Drives tshark (Wireshark's CLI engine) to give an in-app experience close to
Wireshark:

  • a colour-coded live packet list (No / Time / Source / Destination / Protocol
    / Length / Info),
  • click a packet to see its full layer-by-layer dissection,
  • Wireshark display filters (-Y) plus BPF capture filters (-f),
  • a cleartext-credential scan that extracts logins sent in the clear
    (HTTP Basic auth, FTP, Telnet, POP3, IMAP) — the classic demonstration of why
    unencrypted protocols are dangerous.

SCOPE: this is PASSIVE analysis of traffic that already reaches your capture
interface — exactly what Wireshark does. It does not perform interception,
ARP spoofing, or TLS stripping. Use only on networks you are authorised to
monitor. Live capture needs tshark, a capture driver (Npcap on Windows), and
Administrator/root.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Callable, Optional

try:
    from scapy.all import sniff as _scapy_sniff  # type: ignore
except Exception:
    _scapy_sniff = None

_SEP = "\x1f"  # unit separator — won't collide with packet Info text

# Field columns pulled from each packet for the live list.
_FIELDS = ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
           "_ws.col.Protocol", "frame.len", "_ws.col.Info"]

# Protocol → colour category (Wireshark-ish). Credential-bearing cleartext
# protocols are flagged red so they stand out.
COLOR_RULES = {
    # cleartext credential-bearing protocols (flagged red)
    "FTP": "cred", "TELNET": "cred", "POP": "cred", "IMAP": "cred", "SMTP": "cred",
    "HTTP": "http", "HTTP2": "http", "OCSP": "http",
    "TLS": "tls", "SSL": "tls", "QUIC": "tls",
    "DNS": "dns", "MDNS": "dns", "LLMNR": "dns", "NBNS": "dns",
    "SSH": "ssh",
    "RDP": "rdp",
    "SMB": "smb", "SMB2": "smb",
    "KERBEROS": "kerb", "LDAP": "kerb",
    "DHCP": "dhcp", "BOOTP": "dhcp", "DHCPV6": "dhcp",
    "NTP": "ntp", "SNMP": "snmp",
    "SIP": "voip", "RTP": "voip", "RTCP": "voip",
    "ARP": "arp", "ICMPV6": "icmp", "ICMP": "icmp", "IGMP": "icmp",
    "TCP": "tcp", "UDP": "udp",
}
CATEGORY_COLORS = {   # (foreground, background) tuned for the dark theme
    "cred": ("#ffffff", "#8a1519"),   # red — leaked-credential / cleartext risk
    "http": ("#aff0b5", "#10261b"),   # green
    "tls":  ("#d8b9ff", "#1d1733"),   # purple
    "dns":  ("#8fd0ff", "#0d1d31"),   # blue
    "ssh":  ("#7ee0d3", "#0c2420"),   # teal
    "rdp":  ("#ffc48a", "#2a1d0f"),   # orange
    "smb":  ("#e8c99a", "#241c10"),   # tan
    "kerb": ("#ffe08a", "#272012"),   # gold
    "dhcp": ("#9fe8ff", "#0c2430"),   # cyan
    "ntp":  ("#c6d98a", "#1d2410"),   # olive
    "snmp": ("#f0a6e0", "#2a1427"),   # magenta
    "voip": ("#b6a8ff", "#171433"),   # indigo
    "arp":  ("#f0d399", "#241f10"),   # yellow
    "icmp": ("#ff9bb0", "#2a1620"),   # pink
    "tcp":  ("#c9d1d9", "#121722"),   # grey
    "udp":  ("#aebfd0", "#101620"),   # blue-grey
    "other": ("#c9d1d9", "#0d1117"),
}

QUICK_FILTERS = [
    ("All", ""),
    ("HTTP", "http"),
    ("DNS", "dns"),
    ("TLS", "tls"),
    ("TCP", "tcp"),
    ("Cleartext logins", "ftp || telnet || pop || imap || http.authorization"),
    ("ARP", "arp"),
]


def category_for(protocol: str) -> str:
    p = (protocol or "").upper()
    for key, cat in COLOR_RULES.items():
        if key in p:
            return cat
    return "other"


def _tshark() -> Optional[str]:
    p = shutil.which("tshark")
    if p:
        return p
    try:
        from . import tools
        found = tools.REGISTRY_BY_KEY["tshark"].path()  # also adds Wireshark dir to PATH
        if found:
            return found
    except Exception:
        pass
    return shutil.which("tshark")


def backend() -> str:
    if _tshark():
        return "tshark"
    if _scapy_sniff is not None:
        return "scapy"
    return "none"


def backend_help() -> str:
    b = backend()
    if b == "tshark":
        return ("Ready (tshark). Click an interface → Start. Live capture needs "
                "Administrator + Npcap. Click any packet to dissect it.")
    if b == "scapy":
        return "Limited scapy fallback (no dissection view). Install Wireshark for the full experience."
    return ("No capture engine found. Install Wireshark from the Tools tab "
            "(it brings tshark + Npcap), then click ↻.")


def list_interfaces() -> list[str]:
    ts = _tshark()
    if not ts:
        return []
    try:
        out = subprocess.run([ts, "-D"], capture_output=True, text=True, timeout=10)
        ifaces = []
        for line in out.stdout.splitlines():
            line = line.strip()
            if not line or "." not in line:
                continue
            idx, rest = line.split(".", 1)
            name = rest.strip()
            friendly = name[name.rfind("(") + 1:-1] if name.endswith(")") and "(" in name else name
            ifaces.append(f"{idx.strip()}: {friendly}")
        return ifaces
    except Exception:
        return []


class CaptureSession:
    """A running tshark capture that yields structured packet rows + saves a pcap."""

    def __init__(self, interface_label: str, bpf_filter: str = "",
                 display_filter: str = ""):
        self.index = interface_label.split(":", 1)[0].strip() if interface_label else ""
        self.bpf_filter = bpf_filter.strip()
        self.display_filter = display_filter.strip()
        self._proc = None
        self._stop = threading.Event()
        self.count = 0
        self.pcap_path = str(Path(tempfile.gettempdir()) /
                             f"ayarecon_capture_{id(self)}.pcap")

    def start(self, on_packet: Callable[[dict], None],
              on_done: Callable[[str], None]) -> bool:
        ts = _tshark()
        if not ts:
            on_done("No tshark — install Wireshark (Tools tab).")
            return False
        threading.Thread(target=self._run, args=(ts, on_packet, on_done),
                         daemon=True).start()
        return True

    def _run(self, ts, on_packet, on_done):
        # Capture EVERYTHING live (display filters are applied to the saved capture
        # via read_pcap — Wireshark semantics: a display filter hides, never drops).
        cmd = [ts, "-i", self.index or "1", "-l", "-n", "-w", self.pcap_path,
               "--print", "-T", "fields"]
        for fld in _FIELDS:
            cmd += ["-e", fld]
        cmd += ["-E", f"separator={_SEP}"]
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True,
                                          bufsize=1, errors="replace")
        except Exception as exc:
            on_done(f"Could not start tshark: {exc}")
            return
        for line in iter(self._proc.stdout.readline, ""):
            if self._stop.is_set():
                break
            line = line.rstrip("\n")
            if not line:
                continue
            self.count += 1
            on_packet(_parse_fields_line(line))
        err = ""
        try:
            err = self._proc.stderr.read() or ""
        except Exception:
            pass
        try:
            self._proc.terminate()
        except Exception:
            pass
        if self.count == 0:
            low = err.lower()
            if "permission" in low or "npcap" in low or "the capture session could not be initiated" in low:
                on_done("Capture couldn't start — run AyaRecon as Administrator and "
                        "ensure Npcap is installed (Tools tab).")
            elif err.strip():
                on_done("tshark: " + err.strip().splitlines()[-1][:160])
            else:
                on_done("Capture stopped — 0 packets (check the interface / filter).")
        else:
            on_done(f"Capture stopped — {self.count} packets saved.")

    def stop(self):
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass


def _readable_copy(pcap_path: str) -> Optional[str]:
    """
    Return a path we can safely read. While a capture is live, tshark/dumpcap
    holds the pcap open (and Windows may block reads), so we read a copy.
    """
    if not pcap_path or not Path(pcap_path).exists():
        return None
    try:
        import shutil as _sh
        dst = pcap_path + ".read"
        _sh.copyfile(pcap_path, dst)
        return dst
    except Exception:
        return pcap_path  # fall back to the original


def _parse_fields_line(line: str) -> dict:
    parts = line.split(_SEP)
    while len(parts) < len(_FIELDS):
        parts.append("")
    num, t, src, dst, proto, length, info = parts[:len(_FIELDS)]
    try:
        t = f"{float(t):.3f}" if t else ""
    except ValueError:
        pass
    return {"number": num, "time": t, "src": src, "dst": dst,
            "protocol": proto or "?", "length": length, "info": info,
            "category": category_for(proto)}


def read_pcap(pcap_path: str, display_filter: str = "", limit: int = 20000) -> list[dict]:
    """
    Re-read a saved capture, optionally applying a Wireshark display filter (-Y).
    Returns packet dicts. This is how AyaRecon applies display filters reliably
    (and validates filter syntax). Works while a capture is running, on whatever
    has been flushed to disk.
    """
    ts = _tshark()
    read_path = _readable_copy(pcap_path)
    if not ts or not read_path:
        return []
    cmd = [ts, "-r", read_path, "-n", "--print", "-T", "fields"]
    for fld in _FIELDS:
        cmd += ["-e", fld]
    cmd += ["-E", f"separator={_SEP}"]
    if display_filter:
        cmd += ["-Y", display_filter]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                             errors="replace")
    except Exception as exc:
        return [{"number": "", "time": "", "src": "", "dst": "", "protocol": "ERR",
                 "length": "", "info": f"filter error: {exc}", "category": "cred"}]
    if out.returncode != 0 and out.stderr:
        return [{"number": "", "time": "", "src": "", "dst": "", "protocol": "ERR",
                 "length": "", "info": "Invalid display filter: "
                 + out.stderr.strip().splitlines()[-1][:160], "category": "cred"}]
    rows = []
    for line in out.stdout.splitlines():
        if line.strip():
            rows.append(_parse_fields_line(line))
            if len(rows) >= limit:
                break
    return rows


def packet_detail(pcap_path: str, number: str) -> str:
    """Full layer-by-layer dissection of one packet (tshark -V)."""
    ts = _tshark()
    read_path = _readable_copy(pcap_path)
    if not ts or not read_path:
        return "Dissection needs tshark and a saved capture."
    try:
        out = subprocess.run([ts, "-r", read_path, "-n", "-V",
                              "-Y", f"frame.number=={number}"],
                             capture_output=True, text=True, timeout=30,
                             errors="replace")
        text = out.stdout.strip()
        if text:
            return text
        if out.stderr.strip():
            return "tshark: " + out.stderr.strip()
        return ("No detail for this packet yet — if the capture is still running, the "
                "newest packets may not be flushed to disk. Stop the capture and click "
                "again.")
    except Exception as exc:
        return f"Could not read packet detail: {exc}"


def scan_credentials(pcap_path: str) -> list[dict]:
    """
    Extract cleartext credentials/logins from a saved capture. Passive analysis
    that demonstrates why unencrypted protocols leak secrets. Returns a list of
    {proto, src, dst, detail} rows.
    """
    ts = _tshark()
    read_path = _readable_copy(pcap_path)
    if not ts or not read_path:
        return []
    results: list[dict] = []

    def run(filt, fields):
        try:
            out = subprocess.run(
                [ts, "-r", read_path, "-n", "-Y", filt, "-T", "fields",
                 *sum([["-e", f] for f in fields], []), "-E", f"separator={_SEP}"],
                capture_output=True, text=True, timeout=30, errors="replace")
            return [l for l in out.stdout.splitlines() if l.strip()]
        except Exception:
            return []

    # HTTP Basic auth — decode the base64 to user:pass.
    for line in run("http.authorization", ["ip.src", "ip.dst", "http.authorization", "http.host"]):
        src, dst, auth, host = (line.split(_SEP) + ["", "", "", ""])[:4]
        cred = auth
        if auth.lower().startswith("basic "):
            try:
                cred = "Basic → " + base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "replace")
            except Exception:
                pass
        results.append({"proto": "HTTP", "src": src, "dst": dst,
                        "detail": f"{host} {cred}".strip()})

    # FTP USER/PASS
    for line in run('ftp.request.command=="USER" || ftp.request.command=="PASS"',
                    ["ip.src", "ip.dst", "ftp.request.command", "ftp.request.arg"]):
        src, dst, cmd, arg = (line.split(_SEP) + ["", "", "", ""])[:4]
        results.append({"proto": "FTP", "src": src, "dst": dst, "detail": f"{cmd} {arg}"})

    # POP3 / IMAP login commands
    for line in run('pop.request.command=="USER" || pop.request.command=="PASS"',
                    ["ip.src", "ip.dst", "pop.request.command", "pop.request.parameter"]):
        src, dst, cmd, arg = (line.split(_SEP) + ["", "", "", ""])[:4]
        results.append({"proto": "POP3", "src": src, "dst": dst, "detail": f"{cmd} {arg}"})
    for line in run("imap.request", ["ip.src", "ip.dst", "imap.request"]):
        src, dst, req = (line.split(_SEP) + ["", "", ""])[:3]
        if "login" in req.lower():
            results.append({"proto": "IMAP", "src": src, "dst": dst, "detail": req})

    # Telnet data (credentials typed in the clear)
    for line in run("telnet.data", ["ip.src", "ip.dst", "telnet.data"]):
        src, dst, data = (line.split(_SEP) + ["", "", ""])[:3]
        data = (data or "").strip()
        if data:
            results.append({"proto": "TELNET", "src": src, "dst": dst, "detail": data[:120]})

    return results


def launch_wireshark(interface: str = "", bpf_filter: str = "") -> tuple[bool, str]:
    exe = shutil.which("wireshark")
    if not exe:
        try:
            from . import tools
            exe = tools.REGISTRY_BY_KEY["wireshark"].path()
        except Exception:
            exe = None
    if not exe:
        return False, "Wireshark is not installed (see the Tools tab)."
    idx = interface.split(":", 1)[0].strip() if interface else ""
    cmd = [exe]
    if idx:
        cmd += ["-i", idx, "-k"]
    if bpf_filter:
        cmd += ["-f", bpf_filter]
    try:
        subprocess.Popen(cmd)
        return True, "Launched Wireshark."
    except Exception as exc:
        return False, f"Could not launch Wireshark: {exc}"

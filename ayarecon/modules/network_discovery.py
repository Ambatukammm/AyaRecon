"""
AyaRecon — PHASE 0: Network discovery & device inventory.
Made by Ruel.

Builds a picture of the local network WITHOUT interfering with it:

  • Local interfaces — IP, mask, gateway, MAC, and whether this machine's address
    is STATIC or DYNAMIC (read straight from the OS config), plus VPN / VLAN
    recognition.
  • Device inventory — everything in the ARP cache (passive: just reads what the
    OS already learned), enriched with MAC vendor (OUI), hostname (reverse DNS),
    a device-type guess, and an IP-assignment inference.
  • Optional low-impact ARP sweep via nmap (-sn -PR) to fill in quiet hosts — this
    one sends lightweight ARP, so it is gated as an "active" action.

Honesty about IP assignment:
  • This machine: STATIC vs DYNAMIC is read exactly from the OS (DHCP on/off +
    lease). A DHCP *reservation* looks identical to dynamic from the client, so it
    can't be confirmed here — only on the DHCP server.
  • Other devices: a client can't see their DHCP status, so AyaRecon INFERS
    (gateway/infrastructure vs in-DHCP-range) and labels it as an inference.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys

IS_WINDOWS = sys.platform.startswith("win")

# Compact OUI (MAC prefix → vendor) map for common devices. nmap's fuller OUI DB
# is used automatically when a sweep runs; this covers the passive path.
OUI = {
    "FC:FB:FB": "Cisco", "00:1A:A0": "Dell", "00:1B:63": "Apple", "A4:83:E7": "Apple",
    "F0:18:98": "Apple", "3C:06:30": "Apple", "AC:DE:48": "Apple", "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "00:50:56": "VMware",
    "00:0C:29": "VMware", "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft Hyper-V", "D8:3A:DD": "Raspberry Pi", "2C:CF:67": "Raspberry Pi",
    "3C:84:6A": "TP-Link", "50:C7:BF": "TP-Link", "AC:84:C6": "TP-Link", "C0:06:C3": "TP-Link",
    "A0:40:A0": "Netgear", "9C:3D:CF": "Netgear", "20:E5:2A": "Netgear",
    "00:1D:D8": "Microsoft", "C8:3A:35": "Tenda", "F4:F2:6D": "TP-Link",
    "B0:BE:76": "TP-Link", "18:D6:C7": "TP-Link", "D4:6E:0E": "TP-Link",
    "70:4F:57": "Samsung", "5C:0A:5B": "Samsung", "8C:77:12": "Samsung", "FC:A6:21": "Samsung",
    "E0:2B:96": "Amazon", "44:65:0D": "Amazon", "FC:65:DE": "Amazon", "68:54:FD": "Amazon",
    "F0:EF:86": "Google", "1C:F2:9A": "Google", "DA:A1:19": "Google", "54:60:09": "Google",
    "B4:E6:2D": "Espressif(IoT)", "24:0A:C4": "Espressif(IoT)", "7C:9E:BD": "Espressif(IoT)",
    "EC:FA:BC": "Espressif(IoT)", "A0:20:A6": "Espressif(IoT)", "CC:50:E3": "Espressif(IoT)",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips", "00:24:E4": "Withings",
    "74:AC:B9": "Ubiquiti", "FC:EC:DA": "Ubiquiti", "68:D7:9A": "Ubiquiti", "24:5A:4C": "Ubiquiti",
    "48:8F:5A": "MikroTik", "64:D1:54": "MikroTik", "CC:2D:E0": "MikroTik",
    "00:1C:B3": "Apple", "D0:03:4B": "Apple", "F0:99:BF": "Apple",
    "00:25:9C": "Cisco-Linksys", "C8:D7:19": "Cisco", "00:1E:C2": "Apple",
    "B8:3E:59": "Intel", "34:13:E8": "Intel", "9C:B6:D0": "Intel", "50:76:AF": "Intel",
    "00:26:B9": "Dell", "18:03:73": "Dell", "F8:BC:12": "Dell", "D4:BE:D9": "Dell",
    "3C:52:82": "HP", "70:5A:0F": "HP", "00:1F:29": "HP", "A0:D3:C1": "HP",
    "D0:37:45": "Huawei", "48:7B:6B": "Huawei", "00:9A:CD": "Huawei",
    "28:6C:07": "Xiaomi", "64:09:80": "Xiaomi", "F8:A4:5F": "Xiaomi",
}

def _f(category, title, detail="", data=None, severity="info"):
    return {"category": category, "title": title, "detail": detail,
            "data": data or {}, "severity": severity}


VPN_HINTS = ("vpn", "tap", "tun", "wireguard", "wintun", "openvpn", "tailscale",
             "zerotier", "nordvpn", "expressvpn", "anyconnect", "ppp", "pangp",
             "forticlient", "globalprotect", "softether")
VLAN_HINTS = ("vlan", "802.1q", ".1q")


# --------------------------------------------------------------------- interfaces
def local_interfaces() -> list[dict]:
    """Return per-adapter info: name, ip, mask, gateway, mac, dhcp, assignment, vpn/vlan."""
    if IS_WINDOWS:
        return _win_interfaces()
    return _unix_interfaces()


def _win_interfaces() -> list[dict]:
    try:
        out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True,
                             timeout=15, errors="replace").stdout
    except Exception:
        return []
    adapters = []
    cur = None
    for raw in out.splitlines():
        if not raw.strip():
            continue
        # Adapter header: starts at column 0 and ends with ':'
        if not raw.startswith(" ") and raw.rstrip().endswith(":"):
            if cur:
                adapters.append(cur)
            name = raw.rstrip().rstrip(":")
            cur = {"name": name, "ip": "", "mask": "", "gateway": "", "mac": "",
                   "dhcp": None, "dns": "", "lease": "", "desc": "", "ipv6": []}
            continue
        if cur is None:
            continue
        if ":" not in raw:
            continue
        key, _, val = raw.strip().partition(":")
        key = key.strip().lower().rstrip(". ")
        val = val.strip()
        if "description" in key:
            cur["desc"] = val
        elif "physical address" in key:
            cur["mac"] = val.replace("-", ":").upper()
        elif key == "dhcp enabled":
            cur["dhcp"] = val.lower().startswith("yes")
        elif "ipv4 address" in key:
            cur["ip"] = val.split("(")[0].strip()
        elif "ipv6 address" in key:   # includes temporary/link-local variants
            v6 = val.split("(")[0].strip().split("%")[0]
            if v6 and v6 not in cur["ipv6"]:
                cur["ipv6"].append(v6)
        elif key in ("subnet mask",):
            cur["mask"] = val
        elif "default gateway" in key:
            if val:
                cur["gateway"] = val
        elif "dns servers" in key:
            cur["dns"] = val
        elif "lease obtained" in key:
            cur["lease"] = val
    if cur:
        adapters.append(cur)
    for a in adapters:
        _finalize_adapter(a)
    return [a for a in adapters if a.get("ip")]  # keep adapters with an IPv4


def _unix_interfaces() -> list[dict]:
    adapters = []
    try:
        out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True,
                             timeout=10, errors="replace").stdout
    except Exception:
        out = ""
    for line in out.splitlines():
        m = re.search(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        name, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
        adapters.append({"name": name, "ip": ip, "mask": mask, "gateway": "",
                         "mac": "", "dhcp": None, "dns": "", "lease": "", "desc": name,
                         "ipv6": []})
    # IPv6 addresses per adapter.
    try:
        v6out = subprocess.run(["ip", "-o", "-6", "addr"], capture_output=True,
                               text=True, timeout=10, errors="replace").stdout
        for line in v6out.splitlines():
            m = re.search(r"\d+:\s+(\S+)\s+inet6\s+([0-9a-fA-F:]+)/", line)
            if m:
                for a in adapters:
                    if a["name"] == m.group(1) and m.group(2) not in a["ipv6"]:
                        a["ipv6"].append(m.group(2))
    except Exception:
        pass
    for a in adapters:
        _finalize_adapter(a)
    return adapters


def _finalize_adapter(a: dict) -> None:
    text = (a.get("name", "") + " " + a.get("desc", "")).lower()
    a["is_vpn"] = any(h in text for h in VPN_HINTS) or a.get("mask") == "255.255.255.255"
    a["is_vlan"] = any(h in text for h in VLAN_HINTS)
    # Assignment for THIS machine, read from the OS.
    if a.get("dhcp") is True:
        a["assignment"] = "Dynamic (DHCP)"
    elif a.get("dhcp") is False:
        a["assignment"] = "Static (manual)"
    else:
        a["assignment"] = "Unknown"
    a["cidr"] = _cidr_for(a.get("ip"), a.get("mask"))


def _cidr_for(ip: str, mask: str) -> str:
    try:
        if ip and mask:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return str(net)
    except Exception:
        pass
    return ""


def primary_interface(interfaces: list[dict]) -> dict | None:
    """Pick the main LAN adapter (has a gateway, not a VPN) for sweeping."""
    cand = [a for a in interfaces if a.get("gateway") and not a.get("is_vpn")]
    if cand:
        return cand[0]
    nonvpn = [a for a in interfaces if not a.get("is_vpn") and a.get("cidr")]
    return nonvpn[0] if nonvpn else (interfaces[0] if interfaces else None)


# --------------------------------------------------------------------- ARP cache
def arp_table() -> list[tuple[str, str]]:
    """Passively read the OS ARP cache → [(ip, mac)]. Sends no traffic."""
    pairs = []
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=10, errors="replace").stdout
    except Exception:
        return pairs
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}"
                      r"(?:[:-][0-9A-Fa-f]{2}){4})", line)
        if m:
            ip = m.group(1)
            mac = m.group(2).replace("-", ":").upper()
            if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                pairs.append((ip, mac))
    # de-dup keeping first
    seen, out_pairs = set(), []
    for ip, mac in pairs:
        if ip not in seen:
            seen.add(ip)
            out_pairs.append((ip, mac))
    return out_pairs


_NMAP_OUI = None   # lazily-loaded full vendor DB from nmap-mac-prefixes (~40k)


def _load_nmap_oui() -> dict:
    """Load nmap's full MAC-prefix → vendor DB for far better vendor coverage."""
    global _NMAP_OUI
    if _NMAP_OUI is not None:
        return _NMAP_OUI
    _NMAP_OUI = {}
    import os
    import shutil
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes",
        r"C:\Program Files\Nmap\nmap-mac-prefixes",
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/local/share/nmap/nmap-mac-prefixes",
        "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    ]
    nm = shutil.which("nmap")
    if nm:
        d = os.path.dirname(nm)
        candidates.insert(0, os.path.join(d, "nmap-mac-prefixes"))
        candidates.insert(1, os.path.join(d, "..", "share", "nmap", "nmap-mac-prefixes"))
    for path in candidates:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) == 2 and len(parts[0]) == 6:
                            _NMAP_OUI[parts[0].upper()] = parts[1].strip()
                break
        except Exception:
            continue
    return _NMAP_OUI


def oui_vendor(mac: str) -> str:
    if not mac:
        return ""
    parts = mac.upper().split(":")
    if len(parts) < 3:
        return ""
    full = _load_nmap_oui()
    key6 = "".join(parts[:3])
    if key6 in full:
        return full[key6]
    return OUI.get(":".join(parts[:3]), "")


def netbios_name(ip: str, timeout: float = 2.0) -> str:
    """Resolve a Windows/NetBIOS name (small unicast query — used in active mode)."""
    try:
        if IS_WINDOWS:
            out = subprocess.run(["nbtstat", "-A", ip], capture_output=True,
                                 text=True, timeout=timeout, errors="replace").stdout
            for line in out.splitlines():
                # "    HOSTNAME       <00>  UNIQUE      Registered"
                m = re.search(r"^\s*(\S+)\s+<00>\s+UNIQUE", line)
                if m and m.group(1) not in ("", "MSBROWSE"):
                    return m.group(1)
        else:
            import shutil
            if shutil.which("nmblookup"):
                out = subprocess.run(["nmblookup", "-A", ip], capture_output=True,
                                     text=True, timeout=timeout, errors="replace").stdout
                for line in out.splitlines():
                    m = re.search(r"^\s*(\S+)\s+<00>\s+-\s+", line)
                    if m:
                        return m.group(1)
    except Exception:
        pass
    return ""


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)


def _device_type(vendor: str, hostname: str, is_gateway: bool) -> str:
    v = (vendor or "").lower()
    h = (hostname or "").lower()
    if is_gateway:
        return "Router / Gateway"
    if any(k in v for k in ("mikrotik", "ubiquiti", "cisco", "netgear", "tp-link",
                            "tenda", "asus", "d-link")):
        return "Network device"
    if any(k in v for k in ("espressif", "philips", "withings", "tuya", "sonoff")):
        return "IoT / Smart device"
    if any(k in v for k in ("apple",)) or "iphone" in h or "ipad" in h:
        return "Apple device"
    if any(k in v for k in ("samsung", "xiaomi", "huawei")) or "android" in h:
        return "Phone / mobile"
    if any(k in v for k in ("dell", "hp", "intel", "lenovo")):
        return "Computer"
    if any(k in v for k in ("vmware", "virtualbox", "qemu", "hyper-v")):
        return "Virtual machine"
    if any(k in h for k in ("printer", "epson", "canon", "brother")):
        return "Printer"
    return "Unknown"


def _infer_assignment(ip: str, iface: dict | None, is_gateway: bool) -> str:
    """Heuristic IP-assignment for a REMOTE host (can't be known for certain)."""
    if is_gateway:
        return "Static (infrastructure, inferred)"
    try:
        last = int(ip.split(".")[-1])
    except Exception:
        return "Unknown (remote)"
    # Very low / very high addresses are commonly static infra (routers, servers,
    # printers); the broad middle is usually the DHCP pool.
    if last in (1, 254) or last < 10:
        return "Likely static (inferred)"
    if 100 <= last <= 199:
        return "Likely dynamic/DHCP (inferred)"
    return "Unknown (DHCP status not readable from a client)"


# --------------------------------------------------------------------- discovery
def ipv6_neighbors() -> list[tuple[str, str]]:
    """Read the IPv6 neighbour cache (passive) → [(ipv6, mac)]."""
    out_pairs = []
    try:
        if IS_WINDOWS:
            out = subprocess.run(["netsh", "interface", "ipv6", "show", "neighbors"],
                                 capture_output=True, text=True, timeout=12,
                                 errors="replace").stdout
            for line in out.splitlines():
                m = re.match(r"\s*([0-9a-fA-F:]+:[0-9a-fA-F:]+)\s+"
                             r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){4})", line)
                if m:
                    out_pairs.append((m.group(1), m.group(2).replace("-", ":").upper()))
        else:
            out = subprocess.run(["ip", "-6", "neigh"], capture_output=True, text=True,
                                 timeout=10, errors="replace").stdout
            for line in out.splitlines():
                m = re.match(r"([0-9a-fA-F:]+)\s+dev\s+\S+\s+lladdr\s+"
                             r"([0-9a-fA-F:]{17})", line)
                if m:
                    out_pairs.append((m.group(1), m.group(2).upper()))
    except Exception:
        pass
    # de-dup by ipv6
    seen, res = set(), []
    for ip, mac in out_pairs:
        if ip not in seen and not ip.startswith("ff"):  # skip multicast
            seen.add(ip)
            res.append((ip, mac))
    return res


def vlan_vpn_report(vlan_ids: list[str] | None = None) -> list[dict]:
    """
    Analyse whether this host is on a VPN and/or a VLAN-segmented network.
    Reads local config + routing (no traffic). `vlan_ids` (optional) are 802.1Q
    tags observed on the wire by a short passive capture, if one was run.
    Returns finding dicts.
    """
    interfaces = local_interfaces()
    findings = []

    vpns = [a for a in interfaces if a.get("is_vpn")]
    if vpns:
        for a in vpns:
            findings.append(_f("vpn", "VPN adapter active",
                               f"{a['name']} — {a.get('ip','')} ({a.get('desc','')})",
                               {"adapter": a["name"]}, severity="medium"))
    else:
        findings.append(_f("vpn", "No VPN detected",
                           "No VPN tunnel adapter is active on this host.", severity="info"))

    vlan_ifs = [a for a in interfaces if a.get("is_vlan")]
    for a in vlan_ifs:
        findings.append(_f("vlan", "VLAN interface configured",
                           f"{a['name']} — {a.get('ip','')}",
                           {"adapter": a["name"]}, severity="info"))

    cidrs = sorted(set(detected_cidrs(interfaces)) | set(routing_table_networks()))
    if len(cidrs) > 1:
        findings.append(_f("vlan", "Network segmented into multiple subnets",
                           f"{len(cidrs)} subnets reachable (often one per VLAN): "
                           + ", ".join(cidrs[:12]),
                           {"subnets": cidrs}, severity="info"))

    if vlan_ids:
        uniq = sorted(set(str(v) for v in vlan_ids if v))
        if uniq:
            findings.append(_f("vlan", "802.1Q VLAN tags observed",
                               "Tagged frames seen on the wire — VLAN ID(s): "
                               + ", ".join(uniq),
                               {"vlan_ids": uniq}, severity="info"))
    if not vlan_ifs and len(cidrs) <= 1 and not vlan_ids:
        findings.append(_f("vlan", "No VLAN segmentation detected (from this host)",
                           "This host sees a single subnet and no VLAN tags. A host "
                           "usually can't see VLANs it isn't a member of — this isn't "
                           "proof the network lacks VLANs.", severity="info"))

    # IPv6 posture
    v6 = [a for a in interfaces if a.get("ipv6")]
    if v6:
        findings.append(_f("ipv6", "IPv6 active",
                           f"{len(v6)} adapter(s) have IPv6 addresses — remember to "
                           "secure IPv6 too, not just IPv4.", severity="info"))
    return findings


def routing_table_networks() -> list[str]:
    """Networks the OS already knows a route to (accurate, any distance)."""
    nets = []
    try:
        if IS_WINDOWS:
            out = subprocess.run(["route", "print", "-4"], capture_output=True,
                                 text=True, timeout=10, errors="replace").stdout
            for line in out.splitlines():
                m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+", line)
                if m:
                    dest, mask = m.group(1), m.group(2)
                    try:
                        net = ipaddress.IPv4Network(f"{dest}/{mask}", strict=False)
                    except Exception:
                        continue
                    if (net.prefixlen in range(16, 31) and not net.is_multicast
                            and not net.is_loopback and str(net) != "0.0.0.0/0"):
                        nets.append(str(net))
        else:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True,
                                 timeout=10, errors="replace").stdout
            for line in out.splitlines():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+/\d+)\s", line)
                if m:
                    try:
                        net = ipaddress.IPv4Network(m.group(1), strict=False)
                        if 16 <= net.prefixlen <= 30:
                            nets.append(str(net))
                    except Exception:
                        pass
    except Exception:
        pass
    return nets


def classify_target(target: str) -> dict:
    """
    Classify a workflow/scan target so the UI can set expectations.

    Returns {kind, scope, note}:
      kind  = 'private' | 'public' | 'loopback' | 'hostname' | 'range' | 'unknown'
      scope = 'internal' (you see hosts directly) | 'external' (perimeter only)
      note  = plain-English explanation of what a scan will and won't see.
    """
    t = (target or "").strip()
    if not t:
        return {"kind": "unknown", "scope": "external", "note": ""}
    probe = t.split("/")[0]
    try:
        ip = ipaddress.ip_address(probe)
    except ValueError:
        # It's a hostname/domain — resolve to judge, but treat as external by default.
        resolved = ""
        try:
            resolved = socket.gethostbyname(probe)
            ipp = ipaddress.ip_address(resolved)
            if ipp.is_private:
                return {"kind": "hostname", "scope": "internal",
                        "note": f"{probe} resolves to a private address "
                                f"({resolved}) — it's on a local network."}
        except Exception:
            pass
        return {"kind": "hostname", "scope": "external",
                "note": f"{probe} is a public name" +
                        (f" ({resolved})" if resolved else "") +
                        " — you're scanning its internet-facing surface only."}
    if ip.is_loopback:
        return {"kind": "loopback", "scope": "internal",
                "note": "Loopback — this machine itself."}
    if ip.is_private:
        return {"kind": "range" if "/" in t else "private", "scope": "internal",
                "note": "Private address — on a local network. You'll see hosts "
                        "directly only if you're on that network (here, or via VPN)."}
    return {"kind": "range" if "/" in t else "public", "scope": "external",
            "note": "PUBLIC (internet) address. A scan sees only what the firewall/"
                    "router exposes to the outside — forwarded ports and services on "
                    "the gateway itself. Devices behind NAT (192.168.x, 10.x) are NOT "
                    "visible from outside. To reach them remotely, connect a VPN into "
                    "that network first, then scan the private range."}


def auto_scan_ranges(nmap_sweep=None, progress=None) -> dict:
    """
    Work out, with no target given, every network to scan for an 'audit the network
    I'm on' run — INCLUDING anything reachable over an active VPN.

    Returns {"ranges": [cidr,...], "vpn_active": bool, "vpn_names": [...],
             "interfaces": [...]}.

    Unlike auto_subnets (which skips VPN adapters for local-VLAN probing), this
    folds in the VPN's own usable subnet and any routed networks, so testing your
    home network from work works once the VPN is up. Ranges wider than /16 are
    dropped so we never sweep the open internet (e.g. a Tailscale /10).
    """
    interfaces = local_interfaces()
    ranges = set(auto_subnets(interfaces, nmap_sweep, progress))
    ranges.update(routing_table_networks())
    vpns = [a for a in interfaces if a.get("is_vpn")]
    for a in vpns:
        c = a.get("cidr")
        if c:
            try:
                net = ipaddress.IPv4Network(c, strict=False)
                if net.prefixlen < 31:          # skip /31,/32 point-to-point stubs
                    ranges.add(str(net))
            except Exception:
                pass
    # Safety: never auto-sweep anything bigger than a /16.
    safe = []
    for c in ranges:
        try:
            if ipaddress.IPv4Network(c, strict=False).prefixlen >= 16:
                safe.append(c)
        except Exception:
            pass
    safe = sorted(set(safe), key=lambda c: tuple(
        int(x) for x in c.split("/")[0].split(".")))
    return {"ranges": safe, "vpn_active": bool(vpns),
            "vpn_names": [a.get("name", "") for a in vpns],
            "interfaces": interfaces}


def auto_subnets(interfaces: list[dict], nmap_sweep, progress=None) -> list[str]:
    """
    Work out which other subnets/VLANs exist — WITHOUT being told — by:
      1. taking every subnet this host is directly on,
      2. adding every network the routing table knows a route to, and
      3. probing the gateways (.1 and .254) of sibling /24s in each local /16 and
         keeping the ones that answer (a responding gateway = a live VLAN).
    Returns a de-duplicated, sorted list of CIDRs to sweep.

    Limit (physics/routing): a subnet with no route from this host can't be found
    from here — that's how IP works, not a tool gap.
    """
    found = set(detected_cidrs(interfaces))
    found.update(routing_table_networks())

    # Build gateway-probe candidates across each local /16 parent.
    probe_targets = []
    candidate_nets = {}
    for cidr in detected_cidrs(interfaces):
        try:
            net = ipaddress.IPv4Network(cidr)
        except Exception:
            continue
        parent = ipaddress.IPv4Network(f"{net.network_address}/16", strict=False)
        base = int(parent.network_address)
        for third in range(256):
            sub = ipaddress.IPv4Network((base + third * 256, 24))
            key = str(sub)
            if key in found:
                continue
            candidate_nets[str(sub.network_address + 1)] = key    # .1
            candidate_nets[str(sub.network_address + 254)] = key  # .254
            probe_targets.append(str(sub.network_address + 1))
            probe_targets.append(str(sub.network_address + 254))

    if probe_targets and nmap_sweep:
        if progress:
            progress("probing for live VLANs/subnets")
        try:
            # One nmap -sn pass over all gateway candidates (fast ping sweep).
            for host in nmap_sweep(probe_targets):
                ip = host.get("ip")
                if ip in candidate_nets:
                    found.add(candidate_nets[ip])
        except Exception:
            pass

    return sorted(found, key=lambda c: tuple(int(x) for x in
                  c.split("/")[0].split(".")))


def detected_cidrs(interfaces: list[dict]) -> list[str]:
    """All local subnet CIDRs the host sits on (one per VLAN/NIC it has an IP in)."""
    seen, out = set(), []
    for a in interfaces:
        c = a.get("cidr")
        if c and not a.get("is_vpn") and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _local_networks(interfaces):
    nets = []
    for a in interfaces:
        try:
            if a.get("cidr"):
                nets.append(ipaddress.IPv4Network(a["cidr"]))
        except Exception:
            pass
    return nets


def sharper_type(vendor: str, hostname: str, is_gateway: bool,
                 os_text: str = "", ports: list[int] | None = None) -> str:
    """Refine the device-type guess using OS + open ports (from a fingerprint)."""
    ports = ports or []
    os_l = (os_text or "").lower()
    base = _device_type(vendor, hostname, is_gateway)
    if is_gateway:
        return "Router / Gateway"
    if any(p in ports for p in (9100, 515, 631)):
        return "Printer"
    if any(p in ports for p in (554, 8554, 37777)) or "camera" in (hostname or "").lower():
        return "IP camera / NVR"
    if 3389 in ports or "windows server" in os_l:
        return "Windows server" if "server" in os_l else "Windows host"
    if 22 in ports and ("linux" in os_l or "unix" in os_l):
        return "Linux/Unix host"
    if any(p in ports for p in (139, 445)) and "windows" in os_l:
        return "Windows host"
    if "ios" in os_l or "android" in os_l:
        return "Phone / mobile"
    if os_l and base == "Unknown":
        # Fall back to the OS family when we have nothing else.
        for fam in ("windows", "linux", "apple", "macos", "freebsd", "router"):
            if fam in os_l:
                return fam.capitalize() + " device"
    return base


def discover(active: bool = False, ranges=None, nmap_sweep=None,
             netbios: bool = True, progress=None, on_device=None) -> dict:
    """
    Build the device inventory.

    Passive (active=False): reads the ARP cache + local config + reverse DNS —
    sees only this VLAN, sends nothing.

    Active (active=True): runs the supplied nmap sweep across `ranges` (default:
    every subnet this host is on). This is how OTHER VLANs/subnets get scanned —
    routed ICMP/TCP discovery. MAC addresses only come back for the local segment
    (L2 physics); remote hosts get IP + hostname + an inference.

    Returns {"interfaces", "devices", "summary"}.
    """
    interfaces = local_interfaces()
    iface = primary_interface(interfaces)
    gateways = {a.get("gateway") for a in interfaces if a.get("gateway")}
    local_nets = _local_networks(interfaces)

    # Start from the passive ARP cache (ip -> {mac, vendor, hostname}).
    merged: dict[str, dict] = {}
    for ip, mac in arp_table():
        merged[ip] = {"ip": ip, "mac": mac, "vendor": "", "hostname": ""}

    # IPv6 neighbour cache (passive) → map by MAC so we can attach v6 to devices.
    v6_by_mac: dict[str, list] = {}
    for v6, mac in ipv6_neighbors():
        v6_by_mac.setdefault(mac, []).append(v6)

    scanned_ranges = []
    if active and nmap_sweep:
        if ranges:
            scanned_ranges = ([r.strip() for r in ranges.replace(",", " ").split()]
                              if isinstance(ranges, str) else list(ranges))
        else:
            # No ranges given → auto-detect every reachable subnet/VLAN.
            scanned_ranges = auto_subnets(interfaces, nmap_sweep)
        try:
            for host in nmap_sweep(scanned_ranges):
                ip = host.get("ip")
                if not ip:
                    continue
                row = merged.setdefault(ip, {"ip": ip, "mac": "", "vendor": "",
                                             "hostname": ""})
                row["mac"] = row.get("mac") or host.get("mac", "")
                row["vendor"] = row.get("vendor") or host.get("vendor", "")
                row["hostname"] = row.get("hostname") or host.get("hostname", "")
        except Exception:
            pass

    def is_local(ip):
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in n for n in local_nets)
        except Exception:
            return True

    devices = []
    items = list(merged.values())
    for i, row in enumerate(items):
        if progress:
            progress(i + 1, len(items))
        ip = row["ip"]
        mac = row.get("mac", "")
        is_gw = ip in gateways
        local = is_local(ip)
        vendor = row.get("vendor") or oui_vendor(mac)
        hostname = row.get("hostname") or resolve_hostname(ip)
        if not hostname and active and netbios and local:
            hostname = netbios_name(ip)
        if not local:
            assignment = "Remote subnet (routed) — can't read MAC/DHCP"
        elif is_gw:
            assignment = "Static (infrastructure, inferred)"
        elif ip == (iface or {}).get("ip"):
            assignment = (iface or {}).get("assignment", "")
        else:
            assignment = _infer_assignment(ip, iface, is_gw)
        v6list = v6_by_mac.get(mac, []) if mac else []
        dev = {
            "ip": ip, "mac": mac or ("— (remote)" if not local else "—"),
            "vendor": vendor or "unknown",
            "hostname": hostname or "—",
            "type": _device_type(vendor, hostname, is_gw),
            "assignment": assignment,
            "is_gateway": is_gw, "local": local,
            "is_self": ip == (iface or {}).get("ip"),
            "ipv6": v6list,
            "ipv6_str": (v6list[0] + (f"  +{len(v6list)-1}" if len(v6list) > 1 else ""))
                        if v6list else "—",
        }
        devices.append(dev)
        if on_device:
            try:
                on_device(dev)   # stream each device the moment it's resolved
            except Exception:
                pass

    # IPv6-only neighbours (seen in the v6 cache but with no IPv4 entry).
    known_macs = {d["mac"] for d in devices}
    for mac, v6s in v6_by_mac.items():
        if mac and mac not in known_macs:
            vendor = oui_vendor(mac)
            dev = {
                "ip": v6s[0], "mac": mac, "vendor": vendor or "unknown",
                "hostname": resolve_hostname(v6s[0]) or "—",
                "type": _device_type(vendor, "", False),
                "assignment": "IPv6 neighbour", "is_gateway": False, "local": True,
                "is_self": False, "ipv6": v6s,
                "ipv6_str": v6s[0] + (f"  +{len(v6s)-1}" if len(v6s) > 1 else ""),
            }
            devices.append(dev)
            if on_device:
                try:
                    on_device(dev)
                except Exception:
                    pass
    devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")) if
                 d["ip"].count(".") == 3 else (0, 0, 0, 0))

    summary = {
        "iface": iface["name"] if iface else "—",
        "cidr": iface["cidr"] if iface else "—",
        "this_ip": iface["ip"] if iface else "—",
        "this_assignment": iface["assignment"] if iface else "—",
        "vpn": [a["name"] for a in interfaces if a.get("is_vpn")],
        "vlan": [a["name"] for a in interfaces if a.get("is_vlan")],
        "device_count": len(devices),
        "scanned": scanned_ranges,
        "local_cidrs": detected_cidrs(interfaces),
    }
    return {"interfaces": interfaces, "devices": devices, "summary": summary}

# 🛡️ AyaRecon — All-in-One Reconnaissance Cockpit

**Made by Ruel.**

AyaRecon is a Python, GUI-driven security cockpit that brings the whole recon
workflow into **one window** — so a pentester doesn't have to jump between a
dozen apps to scan, enumerate, capture packets, run tools and read results. It
drives the standard tools (nmap, Wireshark/tshark, …), runs a structured
**5-phase workflow**, captures packets live, embeds a real terminal, and uses a
built-in **AI engine** to prioritise findings and write the reports.

> *All-in-one recon cockpit: 5-phase workflow, nmap, live capture, terminal, AI — made by Ruel.*

All data stays **local** in a SQLite database. Passive work is safe by default,
active work requires confirmation, and brute-force / credential-testing modules
are **disabled by default** behind a legal warning and explicit confirmation.

---

## ⚠️ Legal & responsible use

Scanning, enumerating, capturing or testing systems **without explicit written
permission** from the owner is **illegal** in most countries — including
Australia (Criminal Code Act 1995, Part 10.7), the US (CFAA) and the UK
(Computer Misuse Act).

**Only use AyaRecon on systems and networks you own, or are explicitly authorised
to test.** You are solely responsible for how you use it.

- **No exploit code.** Phase 4 identifies vulnerabilities and tells you how to fix
  them; it never exploits them.
- **No online credential/password brute-forcing.** That is an authentication
  attack, not an assessment function, so it's intentionally omitted. The gated
  section hosts read-only wordlist *discovery* only; the credential-testing
  button is a clearly-marked placeholder.

---

## 🧰 What's in the cockpit (the tabs)

| Tab | What it does |
|-----|--------------|
| **Dashboard** | Severity tiles, live security grade, recent findings |
| **Workflow** | The 5-phase engagement (below), plus nmap presets and a one-click full run |
| **Defence** | Self-audit of your own assets with an A–F grade |
| **Capture** | **Live packet capture inside AyaRecon** (pyshark/tshark or scapy) + one-click **open in Wireshark** |
| **Terminal** | A **real embedded shell** (PTY) — run any CLI tool without leaving the app |
| **Tools** | Detects every external tool, shows versions, and gives the exact install command for what's missing |
| **AI Assistant** | Ask about findings, run correlation analysis (offline or via Ollama) |
| **Reports** | Executive / technical / remediation docs → HTML, PDF, CSV, JSON |
| **Settings** | AI provider, API keys, wordlists, timeouts, rate limits, owned assets |

### The 5-phase workflow
1. **Passive Reconnaissance** — DNS, WHOIS, SSL, subdomains (crt.sh), Wayback, breach lookup
2. **Port & Service Scanning** — built-in TCP scanner **+ nmap presets** (XML parsed into findings)
3. **Service Enumeration** — read-only misconfig checks for **SMB, HTTP, DNS, FTP, SMTP, SNMP, LDAP**
4. **Vulnerability Assessment** — **CVE matching** + **misconfiguration detection** (no exploit code)
5. **AI Analysis & Reporting** — prioritisation, plain-English impact, correlation, remediation, reports

Hit **▶ Run full 5-phase workflow** to chain phases 1→4 against a target.

---

## 🔌 Integrated tools

AyaRecon **drives tools you already have** rather than reimplementing them, and
funnels their output into the same findings database:

- **nmap** — run presets or custom scans; results (ports, services, versions, OS)
  parsed from XML and fed into Phase 4 CVE matching.
- **Wireshark / tshark** — in-app live capture via `pyshark`, plus "open in
  Wireshark" for deep dives. `scapy` is the fallback capture backend.
- **Tools tab** also tracks masscan, gobuster, nikto, subfinder, httpx, whois,
  dig and Ollama — detection + install guidance for each.

Adding a new tool is a one-entry change in `ayarecon/integrations/tools.py`.

---

## 📦 Installation

### 1. Requirements
- **Python 3.9+** (Windows 10/11, macOS, or Linux)
- **Tkinter** — bundled with python.org installers; on Linux `sudo apt install python3-tk`

### 2. One-shot setup
```bash
# Windows
setup.bat

# macOS / Linux
./setup.sh
```
By default this **installs everything**: the Python libraries **and** the
external tools. On **Windows** it uses winget and **Chocolatey** (installing
Chocolatey for you if it's missing) and GitHub downloads for the rest; on macOS
it uses Homebrew; on Linux, apt. GitHub-downloaded tools go in a local folder so
they need no admin rights.

> **Windows:** right-click `setup.bat` → **Run as administrator** so the tool
> installers aren't blocked. (winget ships with Windows 10/11 via "App
> Installer"; if it's missing, update that from the Microsoft Store.)

You can also do it from inside the app: the **Tools tab** has **Install
selected**, **Install all missing**, and **Install Python libraries (pip)**
buttons, with live output.

Other modes:
```bash
python install.py --no-auto    # install Python libs + report, but don't touch system tools
python install.py --report     # just show what's installed / missing
python install.py --pip        # only the Python libraries
```

### 3. External tools (install what you need)
AyaRecon runs without them and degrades gracefully, but for full power install:
- **nmap** — `winget install Insecure.Nmap` · `brew install nmap` · `apt install nmap`
- **Wireshark + tshark** (+ Npcap on Windows) — `winget install WiresharkFoundation.Wireshark`
- **Ollama** (offline AI) — https://ollama.com/download, then `ollama pull llama3`

> Live capture needs **admin/root** (and **Npcap** on Windows). The full
> interactive terminal on Windows uses **pywinpty** (`pip install pywinpty`);
> without it, AyaRecon falls back to a piped shell.

**Turning on the AI chat:** on the **AI Assistant** tab click **Install Ollama**,
then **Pull model** (`llama3` by default — a one-time few-GB download), then
**Test AI connection**. The status line says in plain English what's connected or
still needed. The offline analyst (scoring, correlation, remediation) works
regardless — the LLM only adds free-form chat and nicer summaries.

**Don't know the command line?** The **Terminal** tab has **Quick action**
buttons (ping, IP config, DNS lookup, open ports, nmap quick scan, …) — click one
and it runs. Or type a single command in the box and press **Run**.

---

## 🖥️ The embedded terminal — what to expect

AyaRecon hosts a **real PTY shell**: live input, ANSI colours, command history,
and interactive line-based tools (nmap, ssh, python, netcat, sqlmap prompts)
all work. **Honest limit:** a Tk text widget isn't a true terminal grid, so
full-screen TUI apps (fullscreen vim, msfconsole's live UI, `top`) won't redraw
perfectly. For pixel-perfect TUI rendering, the upgrade path is a Qt/xterm.js
front-end — ask and that can be built.

---

## 🗂️ Project structure

```
ayarecon_proj/
├── main.py                       # entry point (GUI / CLI)
├── install.py                    # cross-platform bootstrap (pip + tool detect/guide)
├── setup.bat / setup.sh          # one-click setup launchers
├── requirements.txt
├── README.md
└── ayarecon/
    ├── __init__.py               # metadata + phase definitions (made by Ruel)
    ├── config.py  db.py  permissions.py  scanner.py  util.py  cli.py
    ├── terminal.py               # PTY-backed embedded terminal engine
    ├── modules/
    │   ├── passive.py            # Phase 1
    │   ├── active.py             # Phase 2 (built-in scanner)
    │   ├── enumeration.py        # Phase 3 (SMB/HTTP/DNS/FTP/SMTP/SNMP/LDAP)
    │   ├── vuln_assessment.py    # Phase 4 (CVE + misconfig, no exploit code)
    │   ├── recon_enum.py         # gated wordlist discovery
    │   └── defensive.py          # defensive self-audit + grading
    ├── integrations/
    │   ├── tools.py              # external-tool registry + detection
    │   ├── nmap_tool.py          # nmap subprocess + XML → findings
    │   └── capture.py            # pyshark/scapy capture + launch Wireshark
    ├── ai/engine.py              # Phase 5 — rule-based + optional Ollama/cloud LLM
    ├── reports.py                # 3 docs + HTML/CSV/JSON/PDF export
    └── gui/app.py                # the tabbed cockpit
```

Every scan — GUI or CLI — passes through `scanner.py`, so permission checks,
rate limiting, workspace isolation and the audit log apply throughout (nmap's
exact command line is recorded too).

---

## 📄 License & disclaimer

Provided as-is for **authorised security testing and education only**. The author
(**Ruel**) accepts no liability for misuse. By using AyaRecon you agree to test
only systems and networks you own or are explicitly authorised to assess.

*AyaRecon — made by Ruel.*

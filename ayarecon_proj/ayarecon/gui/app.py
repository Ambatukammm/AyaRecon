"""
AyaRecon — tkinter GUI.
Made by Ruel.

A tabbed cockpit: Dashboard · Workflow · Defence · Capture · Terminal · Tools ·
AI Assistant · Reports · Settings. Scans and captures run on background threads
and push results back to the UI thread via a queue, so the window stays
responsive. All scan actions pass through the Scanner orchestrator, so the
permission + audit layer can never be bypassed from here.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog

from .. import __app_name__, __author__, __version__, __tagline__
from ..config import Config, WORDLIST_DIR, DEFAULT_DB_PATH
from ..db import Database
from ..permissions import (
    PermissionManager, Mode, PERMISSION_PHRASE, LEGAL_WARNING, Decision,
)
from ..ai.engine import AIEngine
from ..scanner import Scanner
from ..modules import defensive, exploitation
from .. import reports
from ..integrations import tools as tools_reg, nmap_tool, capture as capture_mod, nvd
from ..terminal import CommandRunner, parse_ansi, ANSI_COLORS

# Purple theme.
SEV_COLORS = {
    "critical": "#ff5c8a", "high": "#ff8a5c", "medium": "#e0b020",
    "low": "#9b8cff", "info": "#9a8fb5",
}
BG = "#15111f"       # deep purple-black
PANEL = "#1e1830"    # panel
CARD = "#271e40"     # card / selected tab
ACCENT = "#a371f7"   # primary purple
ACCENT2 = "#d7a3ff"  # light lavender (secondary accent)
FG = "#ece6f5"       # near-white lavender text
MUTED = "#9a8fb5"    # muted lavender-grey
BORDER = "#3a2f52"   # subtle purple border


class AyaReconApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.config = Config()
        self.db = Database(DEFAULT_DB_PATH)
        self.perms = PermissionManager(self.config, self.db)
        self.ai = AIEngine(self.config)
        self.scanner = Scanner(self.config, self.db, self.perms, self.ai)

        self.workspace_id = self.db.create_workspace("default")
        self.workspace_name = "default"
        self.event_q: queue.Queue = queue.Queue()

        self._build_style()
        self._build_layout()
        self._require_disclaimer()
        self.refresh_dashboard()
        self.root.after(150, self._drain_queue)

    # ===================================================================== style
    def _build_style(self):
        self.root.title(f"{__app_name__} — Security Recon & Defence · by {__author__}")
        self.root.geometry("1120x720")
        self.root.configure(bg=BG)
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(8, 6, 8, 0))
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED,
                        padding=(18, 9), borderwidth=0, font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", CARD)],
                  foreground=[("selected", "#ffffff"), ("active", FG)])
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("Card.TFrame", background=CARD)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Panel.TLabel", background=PANEL, foreground=FG)
        style.configure("Head.TLabel", background=BG, foreground=FG,
                        font=("Segoe UI", 15, "bold"))
        style.configure("TButton", background=ACCENT, foreground="white",
                        padding=(10, 6), borderwidth=0, font=("Segoe UI", 9))
        style.map("TButton", background=[("active", "#b58cff"), ("pressed", "#7c4dff")])
        style.configure("Ghost.TButton", background=CARD, foreground=FG)
        style.map("Ghost.TButton", background=[("active", "#312550")])
        style.configure("Danger.TButton", background="#b62324", foreground="white")
        style.map("Danger.TButton", background=[("active", "#da3633")])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=FG, borderwidth=0, rowheight=30,
                        font=("Segoe UI", 10))
        style.map("Treeview", background=[("selected", "#7c4dff")],
                  foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background="#241a3a", foreground=MUTED,
                        font=("Segoe UI", 9, "bold"), padding=6, relief="flat")
        style.configure("TEntry", fieldbackground="#120d1e", foreground=FG,
                        borderwidth=1, padding=4)
        style.configure("TCombobox", fieldbackground="#120d1e", foreground=FG, padding=4)
        style.configure("TProgressbar", background=ACCENT, troughcolor=PANEL,
                        borderwidth=0)
        style.configure("TLabelframe", background=BG, borderwidth=1, relief="solid",
                        bordercolor=BORDER)
        style.configure("TLabelframe.Label", background=BG, foreground=ACCENT,
                        font=("Segoe UI", 9, "bold"))

    def _build_layout(self):
        top = tk.Frame(self.root, bg=PANEL, height=60)
        top.pack(fill="x")
        top.pack_propagate(False)
        tk.Label(top, text="🛡  AyaRecon", bg=PANEL, fg="#ffffff",
                 font=("Segoe UI Semibold", 18, "bold")).pack(side="left", padx=(20, 10))
        tk.Label(top, text="all-in-one recon cockpit", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 10)).pack(side="left", pady=(6, 0))
        self.ws_var = tk.StringVar(value=f"● {self.workspace_name}")
        tk.Label(top, textvariable=self.ws_var, bg=PANEL, fg=ACCENT,
                 font=("Segoe UI", 10, "bold")).pack(side="right", padx=20)
        tk.Label(top, text=f"v{__version__} · by {__author__}", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="right", padx=4)
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=12, pady=10)

        # Shared state referenced by tab builders — must exist before building tabs.
        self.status = tk.StringVar(value="Ready.")
        self.gate_var = tk.StringVar()

        self.tab_dash = ttk.Frame(self.nb)
        self.tab_recon = ttk.Frame(self.nb)
        self.tab_def = ttk.Frame(self.nb)
        self.tab_cap = ttk.Frame(self.nb)
        self.tab_term = ttk.Frame(self.nb)
        self.tab_tools = ttk.Frame(self.nb)
        self.tab_ai = ttk.Frame(self.nb)
        self.tab_rep = ttk.Frame(self.nb)
        self.tab_set = ttk.Frame(self.nb)
        for t, label in [
            (self.tab_dash, "  Dashboard  "), (self.tab_recon, "  Workflow  "),
            (self.tab_def, "  Defence  "), (self.tab_cap, "  Capture  "),
            (self.tab_term, "  Terminal  "), (self.tab_tools, "  Tools  "),
            (self.tab_ai, "  AI Assistant  "), (self.tab_rep, "  Reports  "),
            (self.tab_set, "  Settings  "),
        ]:
            self.nb.add(t, text=label)

        self._build_dashboard()
        self._build_recon()
        self._build_defence()
        self._build_capture()
        self._build_terminal()
        self._build_tools()
        self._build_ai()
        self._build_reports()
        self._build_settings()

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self.root, bg=PANEL, height=30)
        bar.pack(fill="x", side="bottom")
        # Busy spinner — animates whenever a background task is running.
        self._busy_count = 0
        self.busy_bar = ttk.Progressbar(bar, mode="indeterminate", length=120)
        self.busy_lbl = tk.Label(bar, text="", bg=PANEL, fg=ACCENT2,
                                 font=("Segoe UI", 9, "bold"))
        tk.Label(bar, textvariable=self.status, bg=PANEL, fg=MUTED,
                 anchor="w").pack(side="left", padx=12)
        tk.Label(bar, textvariable=self.gate_var, bg=PANEL, fg=SEV_COLORS["high"],
                 anchor="e").pack(side="right", padx=12)
        self.busy_bar.pack(side="right", padx=(4, 8), pady=6)
        self.busy_lbl.pack(side="right")
        self._update_gate_label()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------ background tasks
    def _run_bg(self, work):
        """Run work() in a thread and animate the busy spinner while it runs."""
        self.event_q.put(("busy", 1))

        def wrapper():
            try:
                work()
            finally:
                self.event_q.put(("busy", -1))
        threading.Thread(target=wrapper, daemon=True).start()

    def _busy_delta(self, d):
        self._busy_count = max(0, self._busy_count + d)
        if self._busy_count > 0:
            self.busy_lbl.configure(text="working…")
            try:
                self.busy_bar.start(12)
            except Exception:
                pass
        else:
            self.busy_lbl.configure(text="")
            try:
                self.busy_bar.stop()
            except Exception:
                pass

    def _on_close(self):
        # Stop background engines cleanly before exiting.
        try:
            if getattr(self, "term_runner", None):
                self.term_runner.stop()
            if getattr(self, "_capture_session", None):
                self._capture_session.stop()
            self.db.close()
        except Exception:
            pass
        self.root.destroy()

    # ===================================================================== disclaimer
    def _require_disclaimer(self):
        agreed = messagebox.askyesno(
            "AyaRecon — Terms of Use",
            "By using AyaRecon you agree:\n\n"
            "• Only scan systems you OWN or have WRITTEN PERMISSION to test.\n"
            "• Passive OSINT = generally safe.\n"
            "• Active scanning = may be monitored/logged by the target.\n"
            "• Enumeration = ILLEGAL without permission.\n\n"
            "Use responsibly. Made by Ruel.\n\nDo you agree and have authorisation "
            "for the systems you intend to test?",
            icon="warning",
        )
        if not agreed:
            self.root.destroy()
            raise SystemExit(0)

    # ===================================================================== dashboard
    def _build_dashboard(self):
        f = self.tab_dash
        ttk.Label(f, text="Overview", style="Head.TLabel").pack(anchor="w", padx=16, pady=(16, 4))
        self.cards = tk.Frame(f, bg=BG)
        self.cards.pack(fill="x", padx=12, pady=6)
        self.card_vars = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            card = tk.Frame(self.cards, bg=PANEL, width=180, height=90,
                            highlightbackground=SEV_COLORS[sev], highlightthickness=2)
            card.pack(side="left", padx=8, pady=4)
            card.pack_propagate(False)
            v = tk.StringVar(value="0")
            tk.Label(card, textvariable=v, bg=PANEL, fg=SEV_COLORS[sev],
                     font=("Segoe UI", 26, "bold")).pack(pady=(12, 0))
            tk.Label(card, text=sev.upper(), bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 9, "bold")).pack()
            self.card_vars[sev] = v

        grade_row = tk.Frame(f, bg=BG)
        grade_row.pack(fill="x", padx=16, pady=8)
        self.grade_var = tk.StringVar(value="Security grade: —")
        tk.Label(grade_row, textvariable=self.grade_var, bg=BG, fg=FG,
                 font=("Segoe UI", 13, "bold")).pack(side="left")

        rfhead = tk.Frame(f, bg=BG)
        rfhead.pack(fill="x", padx=16, pady=(10, 2))
        ttk.Label(rfhead, text="Recent findings", style="Head.TLabel").pack(side="left")
        tk.Label(rfhead, text="  ·  double-click any finding for the attack path & fix",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        self.dash_tree = self._make_tree(f, ("severity", "category", "title", "detail"))
        self.dash_tree.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        btns = tk.Frame(f, bg=BG)
        btns.pack(fill="x", padx=16, pady=(0, 12))
        ttk.Button(btns, text="Refresh", command=self.refresh_dashboard).pack(side="left")
        ttk.Button(btns, text="Clear findings", style="Danger.TButton",
                   command=self._clear_findings).pack(side="left", padx=8)

    def refresh_dashboard(self):
        counts = self.db.severity_counts(self.workspace_id)
        for sev, v in self.card_vars.items():
            v.set(str(counts.get(sev, 0)))
        g = defensive.grade(counts)
        self.grade_var.set(f"Security grade: {g['grade']}  ({g['score']}/100)")
        findings = self.db.list_findings(self.workspace_id)
        self._fill_tree(self.dash_tree, findings[:200])
        self.status.set(f"{sum(counts.values())} findings in workspace '{self.workspace_name}'.")

    def _clear_findings(self):
        if messagebox.askyesno("Clear findings",
                               "Delete all findings in this workspace?"):
            self.db.clear_findings(self.workspace_id)
            self.refresh_dashboard()

    # ===================================================================== workflow
    def _build_recon(self):
        f = self.tab_recon
        bar = tk.Frame(f, bg=BG)
        bar.pack(fill="x", padx=16, pady=(12, 4))
        tk.Label(bar, text="Target:", bg=BG, fg=FG).pack(side="left")
        self.recon_target = ttk.Entry(bar, width=30)
        self.recon_target.pack(side="left", padx=8)
        self.recon_target.insert(0, "example.com")
        ttk.Button(bar, text="▶ Run full 5-phase workflow",
                   command=self._run_workflow).pack(side="left", padx=8)
        self.phase_var = tk.StringVar(value="")
        tk.Label(bar, textvariable=self.phase_var, bg=BG, fg=ACCENT,
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=8)

        # Scrollable column of phase panels.
        body = tk.Frame(f, bg=BG)
        body.pack(fill="x", padx=16)

        # PHASE 1 — Passive reconnaissance
        p1 = self._phase_frame(body, "1", "Passive Reconnaissance (safe)", MUTED)
        for label, mod in [("DNS", "passive.dns"), ("WHOIS", "passive.whois"),
                           ("SSL cert", "passive.ssl"), ("Subdomains (CT)", "passive.subdomains"),
                           ("Wayback", "passive.wayback"), ("Run all", "passive.all")]:
            ttk.Button(p1, text=label,
                       command=lambda m=mod: self._launch("passive", m)
                       ).pack(side="left", padx=4, pady=6)

        # PHASE 2 — Port & service scanning
        p2 = self._phase_frame(body, "2", "Port & Service Scanning (confirm)", "#e0a800")
        for label, mod in [("Host discovery", "active.ping"),
                           ("Port scan (top 100)", "active.portscan"),
                           ("HTTP fingerprint", "active.http")]:
            ttk.Button(p2, text=label,
                       command=lambda m=mod: self._launch("active", m)
                       ).pack(side="left", padx=4, pady=6)
        tk.Label(p2, text="  nmap:", bg=BG, fg=MUTED).pack(side="left")
        self.nmap_preset = ttk.Combobox(p2, values=list(nmap_tool.PRESETS.keys()),
                                        width=26, state="readonly")
        self.nmap_preset.current(1)
        self.nmap_preset.pack(side="left", padx=4, pady=6)
        ttk.Button(p2, text="Run nmap",
                   command=self._launch_nmap).pack(side="left", padx=4, pady=6)

        # PHASE 3 — Service enumeration (per protocol)
        p3 = self._phase_frame(body, "3", "Service Enumeration (confirm)", "#e0a800")
        for proto in ("HTTP", "DNS", "FTP", "SMTP", "SMB", "SNMP", "LDAP"):
            ttk.Button(p3, text=proto,
                       command=lambda p=proto: self._launch("active", f"enumeration.{p.lower()}")
                       ).pack(side="left", padx=3, pady=6)
        ttk.Button(p3, text="All services",
                   command=lambda: self._launch("active", "enumeration.all")
                   ).pack(side="left", padx=6, pady=6)

        # PHASE 4 — Vulnerability assessment
        p4 = self._phase_frame(body, "4", "Vulnerability Assessment · CVE + misconfig · no exploit code", ACCENT)
        ttk.Button(p4, text="🧪 Run assessment over findings",
                   command=lambda: self._launch("passive", "vuln.assess")
                   ).pack(side="left", padx=4, pady=6)
        ttk.Button(p4, text="🌐 Live CVE check (NVD)",
                   command=self._nvd_enrich).pack(side="left", padx=4, pady=6)
        tk.Label(p4, text="Assessment is offline; NVD check pulls the newest CVEs for "
                          "discovered versions.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 8)).pack(side="left", padx=8)

        # Gated — brute force & credential testing (DISABLED BY DEFAULT)
        ef = tk.LabelFrame(
            f, text=" ⛔ Brute Force & Credential Testing — DISABLED BY DEFAULT ",
            bg=BG, fg="#d9534f", labelanchor="nw", bd=2)
        ef.pack(fill="x", padx=16, pady=(10, 4))
        self.enable_bruteforce = tk.BooleanVar(value=False)
        warn = ("⚠ LEGAL WARNING: brute force / credential testing without WRITTEN "
                "PERMISSION is illegal. Discovery modules below are locked until you "
                "unlock the gate and tick the box.")
        tk.Label(ef, text=warn, bg=BG, fg="#d9534f", wraplength=980, justify="left",
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=6, pady=(4, 2))
        row = tk.Frame(ef, bg=BG)
        row.pack(fill="x")
        ttk.Button(row, text="🔒 Unlock permission gate",
                   command=self._unlock_gate).pack(side="left", padx=5, pady=6)
        tk.Checkbutton(row, text="I have written permission — enable this section",
                       variable=self.enable_bruteforce, bg=BG, fg=FG,
                       selectcolor=BG, activebackground=BG, activeforeground=FG,
                       command=self._toggle_bruteforce).pack(side="left", padx=8)
        row2 = tk.Frame(ef, bg=BG)
        row2.pack(fill="x")
        ttk.Button(row2, text="Directory discovery",
                   command=lambda: self._launch("enumeration", "enum.directories")
                   ).pack(side="left", padx=5, pady=6)
        ttk.Button(row2, text="Subdomain discovery",
                   command=lambda: self._launch("enumeration", "enum.subdomains")
                   ).pack(side="left", padx=5, pady=6)
        ttk.Button(row2, text="Credential testing",
                   command=self._credential_placeholder).pack(side="left", padx=5, pady=6)
        tk.Label(ef, text="Note: online password/credential brute-forcing is intentionally "
                          "not implemented in this build — see README.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", padx=6, pady=(0, 4))

        self.recon_prog = ttk.Progressbar(f, mode="determinate")
        self.recon_prog.pack(fill="x", padx=16, pady=(6, 2))
        rhead = tk.Frame(f, bg=BG)
        rhead.pack(fill="x", padx=16, pady=(2, 2))
        ttk.Label(rhead, text="Results", style="Head.TLabel").pack(side="left")
        tk.Label(rhead, text="  ·  double-click a finding to see how it can be exploited "
                             "and how to fix it",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        self.recon_tree = self._make_tree(f, ("severity", "category", "title", "detail"))
        self.recon_tree.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def _phase_frame(self, parent, num, title, color):
        lf = tk.LabelFrame(parent, text=f"  Phase {num} · {title}  ", bg=BG, fg=color,
                           labelanchor="nw", bd=1)
        lf.pack(fill="x", pady=4)
        return lf

    def _toggle_bruteforce(self):
        if self.enable_bruteforce.get():
            messagebox.showwarning("Legal warning", LEGAL_WARNING)

    def _credential_placeholder(self):
        messagebox.showinfo(
            "Credential testing — not implemented",
            "This build of AyaRecon does not include online credential / password "
            "brute-forcing. That is an authentication attack rather than an audit "
            "function, so it is intentionally omitted.\n\n"
            "To assess your OWN login's resistance to weak passwords, do so against "
            "an account you control, through a consented password-strength review or "
            "an offline hash-strength audit of your own password database — not by "
            "sending guesses at a live endpoint.\n\nMade by Ruel.")

    def _run_workflow(self):
        target = self.recon_target.get().strip()
        if not target:
            messagebox.showwarning("Target required", "Enter a target first.")
            return
        confirmed = messagebox.askyesno(
            "Confirm full workflow",
            f"The full workflow runs active scanning and service enumeration against "
            f"{target} (phases 2–3 make direct contact and may be logged).\n\n"
            "Do you have authorisation to test this target?")
        if not confirmed:
            return
        self.status.set("Running full 5-phase workflow …")

        def phase_cb(label):
            self.event_q.put(("phase", label))

        def work():
            dec, findings = self.scanner.run_full_workflow(
                self.workspace_id, target, confirmed=True, phase_cb=phase_cb)
            self.event_q.put(("scan_done", ("workflow", self.recon_tree, dec, findings)))
        self._run_bg(work)

    # ===================================================================== defence
    def _build_defence(self):
        f = self.tab_def
        bar = tk.Frame(f, bg=BG)
        bar.pack(fill="x", padx=16, pady=12)
        tk.Label(bar, text="Your asset (IP/domain):", bg=BG, fg=FG).pack(side="left")
        self.def_target = ttk.Entry(bar, width=30)
        self.def_target.pack(side="left", padx=8)
        ttk.Button(bar, text="Mark as owned",
                   command=self._mark_owned).pack(side="left", padx=4)
        ttk.Button(bar, text="🛡️ Run self-audit",
                   command=lambda: self._launch("defensive", "defensive.self_audit")
                   ).pack(side="left", padx=4)
        ttk.Button(bar, text="Privacy footprint",
                   command=lambda: self._launch("defensive", "defensive.privacy")
                   ).pack(side="left", padx=4)

        tk.Label(f, text="Defence mode runs the full checks against YOUR assets, then "
                         "grades your exposure. Register the asset as owned first.",
                 bg=BG, fg=MUTED, wraplength=900, justify="left").pack(anchor="w", padx=16)

        self.def_grade = tk.StringVar(value="Grade: —")
        tk.Label(f, textvariable=self.def_grade, bg=BG, fg=FG,
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=16, pady=8)

        self.def_tree = self._make_tree(f, ("severity", "category", "title", "detail"))
        self.def_tree.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    # ===================================================================== nmap
    def _launch_nmap(self):
        target = self.recon_target.get().strip()
        if not target:
            messagebox.showwarning("Target required", "Enter a target first.")
            return
        preset = self.nmap_preset.get()
        if not nmap_tool.available():
            messagebox.showinfo(
                "nmap not installed",
                "nmap isn't on your PATH. Install it from the Tools tab, then retry.")
            return
        if not messagebox.askyesno(
                "Confirm nmap scan",
                f"Run nmap '{preset}' against {target}?\n\nnmap makes direct contact "
                "and may be logged. Do you have authorisation?"):
            return
        self.status.set(f"Running nmap ({preset}) against {target} … this can take a while.")

        def work():
            dec, findings = self.scanner.run(
                self.workspace_id, target, "active", "nmap.scan",
                confirmed=True, confirmation_text="nmap scan", preset=preset)
            self.event_q.put(("scan_done", ("active", self.recon_tree, dec, findings)))
        self._run_bg(work)

    def _nvd_enrich(self):
        if not nvd.available():
            messagebox.showinfo("Live CVE check",
                                "The 'requests' library is needed. Install it from the "
                                "Tools tab (Install Python libraries), then retry.")
            return
        findings = self.db.list_findings(self.workspace_id)
        products = {(f.get("data", {}) or {}).get("product") for f in findings}
        products = {p for p in products if p and len(p) > 3}
        if not products:
            messagebox.showinfo("Live CVE check",
                                "No service/version banners found yet. Run Phase 2–3 "
                                "(nmap / service enumeration) first so there are products "
                                "to look up.")
            return
        self.status.set(f"Querying NVD for {len(products)} product(s)… (rate-limited)")
        key = self.config.get("nvd_api_key", "")

        def work():
            new = nvd.enrich_findings(
                findings, api_key=key,
                progress=lambda i, n: self.event_q.put(
                    ("phase", f"NVD lookup {i}/{n}")))
            for f in new:
                self.db.add_finding(
                    self.workspace_id, f.get("target", ""), "vuln", f["title"],
                    f["detail"], f.get("data", {}), f["severity"],
                    ai_reasoning=f.get("ai_reasoning", ""),
                    remediation=f.get("remediation", ""))
            self.event_q.put(("scan_done", ("passive", self.recon_tree,
                                            Decision(True, "NVD live CVE check"), new)))
        self._run_bg(work)

    # ===================================================================== capture
    def _build_capture(self):
        f = self.tab_cap
        head = tk.Frame(f, bg=BG)
        head.pack(fill="x", padx=16, pady=(12, 2))
        ttk.Label(head, text="Packet Capture & Analysis", style="Head.TLabel").pack(side="left")
        self.cap_count = tk.StringVar(value="0 packets")
        tk.Label(head, textvariable=self.cap_count, bg=BG, fg=ACCENT,
                 font=("Segoe UI", 10, "bold")).pack(side="right")
        self.cap_status = tk.StringVar(value=capture_mod.backend_help())
        tk.Label(f, textvariable=self.cap_status, bg=BG, fg=MUTED,
                 wraplength=1000, justify="left").pack(anchor="w", padx=16)

        # Row 1 — interface + capture (BPF) filter + controls
        bar = tk.Frame(f, bg=BG)
        bar.pack(fill="x", padx=16, pady=(8, 2))
        tk.Label(bar, text="Interface:", bg=BG, fg=FG).pack(side="left")
        self.cap_iface = ttk.Combobox(bar, width=26, values=[])
        self.cap_iface.pack(side="left", padx=6)
        ttk.Button(bar, text="↻", width=3, command=self._cap_refresh).pack(side="left")
        self.cap_start_btn = ttk.Button(bar, text="▶ Start", command=self._cap_start)
        self.cap_start_btn.pack(side="left", padx=(10, 4))
        ttk.Button(bar, text="■ Stop", command=self._cap_stop,
                   style="Danger.TButton").pack(side="left", padx=4)
        ttk.Button(bar, text="🔑 Scan for cleartext logins",
                   command=self._cap_scan_creds).pack(side="left", padx=4)
        ttk.Button(bar, text="🦈 Wireshark", style="Ghost.TButton",
                   command=self._launch_wireshark).pack(side="left", padx=4)

        # Row 2 — Wireshark display filter + quick-filter chips
        fbar = tk.Frame(f, bg=BG)
        fbar.pack(fill="x", padx=16, pady=(2, 4))
        tk.Label(fbar, text="Display filter:", bg=BG, fg=FG).pack(side="left")
        self.cap_dfilter = ttk.Entry(fbar)
        self.cap_dfilter.pack(side="left", fill="x", expand=True, padx=6)
        self.cap_dfilter.insert(0, "")
        self.cap_dfilter.bind("<Return>", lambda e: self._cap_apply_filter())
        ttk.Button(fbar, text="Apply", command=self._cap_apply_filter).pack(side="left", padx=(0, 6))
        for label, flt in capture_mod.QUICK_FILTERS:
            ttk.Button(fbar, text=label, style="Ghost.TButton",
                       command=lambda ff=flt: self._cap_set_filter(ff)).pack(side="left", padx=2)
        # Hidden BPF capture filter is folded into the display filter box for simplicity.
        self.cap_filter = ttk.Entry(f)  # kept for Wireshark-launch BPF compatibility

        # Packet list (colored) over a dissection pane.
        paned = tk.PanedWindow(f, orient="vertical", bg=BG, bd=0, sashwidth=6,
                               sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        wrap = tk.Frame(paned, bg=BG)
        self.cap_tree = ttk.Treeview(wrap, columns=cols, show="headings", height=14)
        heads = {"no": "No.", "time": "Time", "src": "Source", "dst": "Destination",
                 "proto": "Protocol", "len": "Len", "info": "Info"}
        widths = {"no": 60, "time": 80, "src": 150, "dst": 150, "proto": 80,
                  "len": 55, "info": 420}
        for c in cols:
            self.cap_tree.heading(c, text=heads[c])
            self.cap_tree.column(c, width=widths[c], anchor="w")
        for cat, (fg, bgc) in capture_mod.CATEGORY_COLORS.items():
            self.cap_tree.tag_configure(cat, foreground=fg, background=bgc)
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.cap_tree.yview)
        self.cap_tree.configure(yscrollcommand=vs.set)
        self.cap_tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.cap_tree.bind("<<TreeviewSelect>>", self._cap_on_select)
        paned.add(wrap, stretch="always")

        self.cap_detail = scrolledtext.ScrolledText(paned, height=12, bg="#0a0c11",
                                                    fg="#cfe0cf", relief="flat",
                                                    font=("Consolas", 9), wrap="word")
        self.cap_detail.insert("end", "Click a packet above to dissect it layer by layer "
                               "(like Wireshark's detail pane).\n")
        self.cap_detail.configure(state="disabled")
        paned.add(self.cap_detail)

        self._capture_session = None
        self._cap_n = 0
        self._cap_packets = {}   # tree iid -> packet dict
        self._last_pcap = None   # kept after Stop so packets stay inspectable
        self._cap_refresh()      # populate interfaces in the background

    def _cap_set_filter(self, flt):
        self.cap_dfilter.delete(0, "end")
        self.cap_dfilter.insert(0, flt)
        self._cap_apply_filter()

    def _cap_apply_filter(self):
        """Apply the Wireshark display filter to the captured packets (re-reads pcap)."""
        if not self._last_pcap:
            self.status.set("Nothing captured yet — Start a capture, then filter it.")
            return
        dfilter = self.cap_dfilter.get().strip()
        pcap = self._last_pcap
        self.status.set("⏳ Applying filter…")

        def work():
            rows = capture_mod.read_pcap(pcap, dfilter)
            self.event_q.put(("cap_filtered", rows))
        self._run_bg(work)

    def _cap_refresh(self):
        self.cap_status.set("Detecting interfaces…")

        def work():
            ifaces = capture_mod.list_interfaces()
            self.event_q.put(("cap_ifaces", ifaces))
        self._run_bg(work)

    def _cap_start(self):
        if self._capture_session:
            messagebox.showinfo("Capture", "A capture is already running — Stop it first.")
            return
        if capture_mod.backend() == "none":
            messagebox.showwarning(
                "No capture engine",
                "AyaRecon couldn't find tshark. Install Wireshark from the Tools tab "
                "(it brings tshark + Npcap), then click ↻ here. Capture also needs "
                "AyaRecon to be run as Administrator.")
            return
        iface = self.cap_iface.get().strip()
        self.cap_tree.delete(*self.cap_tree.get_children())
        self._cap_packets = {}
        self._cap_n = 0
        self.cap_count.set("0 packets")
        self._capture_session = capture_mod.CaptureSession(iface, "", "")
        self._last_pcap = self._capture_session.pcap_path
        ok = self._capture_session.start(
            on_packet=lambda p: self.event_q.put(("packet", p)),
            on_done=lambda m: self.event_q.put(("cap_done", m)))
        if ok:
            self.status.set(f"Capturing on {iface or 'default'} …")
            self.cap_status.set("Capturing… click any packet to dissect it. If nothing "
                                "appears: run as Administrator and check the interface.")
        else:
            self._capture_session = None

    def _cap_stop(self):
        if self._capture_session:
            self._capture_session.stop()
            self.status.set("Capture stopping …")

    def _cap_show_rows(self, rows):
        """Replace the list with a filtered snapshot (from read_pcap)."""
        self.cap_tree.delete(*self.cap_tree.get_children())
        self._cap_packets = {}
        for p in rows:
            cat = p.get("category", "other")
            iid = self.cap_tree.insert(
                "", "end", tags=(cat,),
                values=(p["number"], p["time"], p["src"], p["dst"],
                        p["protocol"], p["length"], (p["info"] or "")[:400]))
            self._cap_packets[iid] = p
        flt = self.cap_dfilter.get().strip()
        self.cap_count.set(f"{len(rows)} shown" + (f" · filter: {flt}" if flt else ""))
        self.status.set(f"Filter applied — {len(rows)} packets match.")

    def _cap_add_packet(self, p):
        cat = p.get("category", "other")
        iid = self.cap_tree.insert(
            "", "end", tags=(cat,),
            values=(p["number"], p["time"], p["src"], p["dst"],
                    p["protocol"], p["length"], (p["info"] or "")[:400]))
        self._cap_packets[iid] = p
        self._cap_n += 1
        if self._cap_n % 10 == 0:
            self.cap_tree.see(iid)
        self.cap_count.set(f"{self._cap_n} packets")

    def _cap_on_select(self, event):
        sel = self.cap_tree.selection()
        if not sel:
            return
        p = self._cap_packets.get(sel[0])
        if not p:
            return
        if not self._last_pcap:
            self._cap_detail_set("No capture to read yet — start a capture first.")
            return
        self._cap_detail_set(f"⏳ Dissecting packet #{p['number']} …\n")
        pcap = self._last_pcap

        def work():
            text = capture_mod.packet_detail(pcap, p["number"])
            self.event_q.put(("cap_detail", text))
        self._run_bg(work)

    def _cap_detail_set(self, text):
        self.cap_detail.configure(state="normal")
        self.cap_detail.delete("1.0", "end")
        self.cap_detail.insert("end", text)
        self.cap_detail.configure(state="disabled")

    def _cap_scan_creds(self):
        if not self._last_pcap:
            messagebox.showinfo("Scan", "Start a capture first (then stop it, or scan "
                                "while it runs) so there are packets to analyse.")
            return
        pcap = self._last_pcap
        self._cap_detail_set("⏳ Scanning capture for cleartext credentials …\n")

        def work():
            creds = capture_mod.scan_credentials(pcap)
            if creds:
                lines = ["⚠ CLEARTEXT CREDENTIALS / LOGINS FOUND "
                         "(these protocols send secrets unencrypted):\n"]
                for c in creds:
                    lines.append(f"  [{c['proto']}] {c['src']} → {c['dst']}\n"
                                 f"      {c['detail']}")
                lines.append("\nFix: move these services to encrypted equivalents "
                             "(HTTPS, FTPS/SFTP, SSH, POP3S/IMAPS) and never send "
                             "credentials over cleartext protocols.")
                text = "\n".join(lines)
            else:
                text = ("No cleartext credentials found in the capture so far. That's "
                        "good — or the logins were over TLS, or none were captured yet.")
            self.event_q.put(("cap_detail", text))
        self._run_bg(work)

    def _launch_wireshark(self):
        ok, msg = capture_mod.launch_wireshark(self.cap_iface.get().strip(), "")
        self.status.set(msg)
        if not ok:
            messagebox.showinfo("Wireshark", msg)

    # OS-aware quick commands for users who'd rather click than type.
    # {button label: command}. Some use {target} filled from the Workflow target.
    def _quick_commands(self) -> list[tuple[str, str]]:
        import sys as _sys
        if _sys.platform.startswith("win"):
            return [
                ("My IP config", "ipconfig"),
                ("Ping target", "ping -n 4 {target}"),
                ("DNS lookup", "nslookup {target}"),
                ("Open ports (me)", "netstat -ano"),
                ("Trace route", "tracert {target}"),
                ("ARP table", "arp -a"),
                ("Who am I", "whoami"),
                ("nmap quick", "nmap -T4 -F {target}"),
            ]
        return [
            ("My IP config", "ip addr || ifconfig"),
            ("Ping target", "ping -c 4 {target}"),
            ("DNS lookup", "dig {target} +short || nslookup {target}"),
            ("Open ports (me)", "ss -tulpn || netstat -tulpn"),
            ("Trace route", "traceroute {target}"),
            ("ARP table", "arp -a"),
            ("Who am I", "id"),
            ("nmap quick", "nmap -T4 -F {target}"),
        ]

    def _build_terminal(self):
        f = self.tab_term
        bar = tk.Frame(f, bg=BG)
        bar.pack(fill="x", padx=16, pady=(12, 4))
        tk.Label(bar, text="Terminal — click a quick action, or type a command and press Run. "
                           "Output streams below.",
                 bg=BG, fg=MUTED).pack(side="left")
        ttk.Button(bar, text="Clear",
                   command=self._term_clear).pack(side="right", padx=6)
        ttk.Button(bar, text="Stop (Ctrl-C)",
                   command=lambda: self._term_send_ctrl_c(),
                   style="Danger.TButton").pack(side="right", padx=6)

        # Quick-command buttons (no CLI knowledge needed).
        qc = tk.LabelFrame(f, text=" Quick actions (click to run) ", bg=BG, fg=MUTED,
                           labelanchor="nw", bd=1)
        qc.pack(fill="x", padx=16, pady=(2, 4))
        for label, cmd in self._quick_commands():
            ttk.Button(qc, text=label,
                       command=lambda c=cmd: self._term_quick(c)).pack(
                side="left", padx=3, pady=5)

        # Read-only output pane (stable: we render shell output, we never try to
        # echo individual keystrokes — that was the source of the earlier glitches).
        self.term_text = tk.Text(f, bg="#0a0c11", fg="#dcdfe4", relief="flat",
                                 font=("Consolas", 10), wrap="char", state="disabled")
        self.term_text.pack(fill="both", expand=True, padx=16, pady=(4, 4))
        for tag, color in ANSI_COLORS.items():
            self.term_text.tag_configure(tag, foreground=color)
        self._term_set("AyaRecon terminal — click a Quick action, or type a command below "
                       "and press Run. Made by Ruel.\n")

        # Command line: type one command, press Enter/Run.
        runbar = tk.Frame(f, bg=BG)
        runbar.pack(fill="x", padx=16, pady=(0, 14))
        tk.Label(runbar, text="Command:", bg=BG, fg=FG).pack(side="left")
        self.term_cmd = ttk.Entry(runbar)
        self.term_cmd.pack(side="left", fill="x", expand=True, padx=6)
        self.term_cmd.bind("<Return>", lambda e: self._term_run_entry())
        self.term_cmd.bind("<Up>", lambda e: self._term_history(-1))
        self.term_cmd.bind("<Down>", lambda e: self._term_history(1))
        ttk.Button(runbar, text="Run", command=self._term_run_entry).pack(side="left")
        self.term_runner = None
        self._term_hist = []
        self._term_hist_i = 0

    def _term_set(self, text):
        self.term_text.configure(state="normal")
        self.term_text.insert("end", text)
        self.term_text.see("end")
        self.term_text.configure(state="disabled")

    def _term_clear(self):
        self.term_text.configure(state="normal")
        self.term_text.delete("1.0", "end")
        self.term_text.configure(state="disabled")

    def _term_history(self, step):
        if not self._term_hist:
            return "break"
        self._term_hist_i = max(0, min(len(self._term_hist),
                                       self._term_hist_i + step))
        self.term_cmd.delete(0, "end")
        if self._term_hist_i < len(self._term_hist):
            self.term_cmd.insert(0, self._term_hist[self._term_hist_i])
        return "break"

    def _term_ensure(self):
        if self.term_runner is None:
            self.term_runner = CommandRunner(
                on_output=lambda t: self.event_q.put(("term", t)),
                on_done=lambda rc: self.event_q.put(("term_done", rc)))
        return self.term_runner

    def _term_send_ctrl_c(self):
        if self.term_runner:
            self.term_runner.stop()
            self.status.set("Stopped running command.")

    def _term_quick(self, template: str):
        target = self.recon_target.get().strip() if hasattr(self, "recon_target") else ""
        if "{target}" in template and not target:
            messagebox.showinfo("Target needed",
                                "Enter a target on the Workflow tab first — this quick "
                                "action uses it.")
            return
        cmd = template.replace("{target}", target)
        self._term_set(f"\n> {cmd}\n")
        self._term_ensure().run(cmd)

    def _term_run_entry(self):
        cmd = self.term_cmd.get().strip()
        if not cmd:
            return
        self._term_hist.append(cmd)
        self._term_hist_i = len(self._term_hist)
        self.term_cmd.delete(0, "end")
        self._term_set(f"\n> {cmd}\n")
        self._term_ensure().run(cmd)

    def _term_write(self, text):
        if text == "\x00CLEAR\x00":
            self._term_clear()
            return
        self.term_text.configure(state="normal")
        for seg, tag in parse_ansi(text):
            if not seg:
                continue
            if tag:
                self.term_text.insert("end", seg, (tag,))
            else:
                self.term_text.insert("end", seg)
        self.term_text.see("end")
        self.term_text.configure(state="disabled")

    # ===================================================================== tools
    def _build_tools(self):
        f = self.tab_tools
        head = tk.Frame(f, bg=BG)
        head.pack(fill="x", padx=16, pady=(14, 4))
        ttk.Label(head, text="Tools & Dependencies", style="Head.TLabel").pack(side="left")
        ttk.Button(head, text="↻ Re-check", command=self._refresh_tools).pack(side="right")
        tk.Label(f, text=f"Platform: {tools_reg.current_os()} · AyaRecon installs tools "
                         "for you — winget/Chocolatey on Windows (it will set up "
                         "Chocolatey automatically), brew on macOS, apt on Linux, and "
                         "GitHub downloads for the rest. Tip: on Windows, launch AyaRecon "
                         "as Administrator so installs aren't blocked.",
                 bg=BG, fg=MUTED, wraplength=940, justify="left").pack(anchor="w", padx=16)

        btns = tk.Frame(f, bg=BG)
        btns.pack(fill="x", padx=16, pady=(6, 2))
        ttk.Button(btns, text="⬇ Install selected",
                   command=self._install_selected).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="⬇ Install all missing",
                   command=self._install_all_missing).pack(side="left", padx=6)
        ttk.Button(btns, text="🐍 Install Python libraries (pip)",
                   command=self._pip_install).pack(side="left", padx=6)
        tk.Label(btns, text="(⚡ = auto-installable here)", bg=BG, fg=MUTED,
                 font=("Segoe UI", 8)).pack(side="left", padx=8)

        cols = ("status", "name", "category", "version", "install")
        self.tools_tree = ttk.Treeview(f, columns=cols, show="headings", height=10)
        widths = {"status": 90, "name": 150, "category": 100, "version": 200, "install": 400}
        for c in cols:
            self.tools_tree.heading(c, text=c.capitalize())
            self.tools_tree.column(c, width=widths.get(c, 120), anchor="w")
        self.tools_tree.tag_configure("ok", foreground="#98c379")
        self.tools_tree.tag_configure("miss", foreground="#d9534f")
        self.tools_tree.pack(fill="both", expand=True, padx=16, pady=6)
        self.tools_tree.bind("<Double-1>", self._tool_copy_hint)

        self.tools_log = scrolledtext.ScrolledText(f, height=8, bg="#0a0c11", fg="#cfe0cf",
                                                   relief="flat", font=("Consolas", 9))
        self.tools_log.pack(fill="x", expand=False, padx=16, pady=(4, 12))
        self.tools_log.insert("end", "Install output appears here. "
                              "Double-click a tool to copy its command.\n")
        self._tool_iid_key = {}
        self._installing = False
        self.tools_tree.tag_configure("opt", foreground=MUTED)
        # Detection runs subprocesses per tool, so do it in the background to keep
        # startup instant.
        self.tools_tree.insert("", "end", values=("detecting…", "", "", "", ""))
        self._refresh_tools()

    def _refresh_tools(self):
        def work():
            rows = tools_reg.detect_all()
            self.event_q.put(("tools_rows", rows))
        self._run_bg(work)

    def _fill_tools(self, rows):
        self.tools_tree.delete(*self.tools_tree.get_children())
        self._tool_iid_key = {}
        self._tool_rows = rows
        for r in rows:
            if r["installed"]:
                tag, status = "ok", "✓ ready"
            elif r.get("optional"):
                tag, status = "opt", "○ optional"
            else:
                tag = "miss"
                status = "⚡ installable" if r.get("can_auto") else "✗ missing"
            install = r["version"] if r["installed"] else r["hint"]
            iid = self.tools_tree.insert("", "end", tags=(tag,),
                                         values=(status, r["name"], r["category"],
                                                 r["version"] or "—", install))
            self._tool_iid_key[iid] = r["key"]
        n_ok = sum(1 for r in rows if r["installed"])
        self.status.set(f"Tools: {n_ok}/{len(rows)} installed.")

    def _tool_copy_hint(self, event):
        sel = self.tools_tree.selection()
        if not sel:
            return
        vals = self.tools_tree.item(sel[0], "values")
        name, install = vals[1], vals[4]
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(install)
            self.status.set(f"Copied install command for {name}.")
        except Exception:
            pass

    def _install_log(self, line):
        self.event_q.put(("install_log", line))

    def _run_installs(self, keys):
        if self._installing:
            return
        if not keys:
            messagebox.showinfo("Install", "Nothing to install — select a missing tool, "
                                "or everything is already installed.")
            return
        self._installing = True

        def work():
            ok, failed = [], []
            for k in keys:
                self._install_log(f"\n=== Installing {k} ===")
                rc = tools_reg.install_tool(k, on_line=self._install_log)
                (ok if rc == 0 else failed).append(k)
            self._install_log("\n" + "=" * 40)
            self._install_log(f"SUMMARY: installed {len(ok)} "
                              f"({', '.join(ok) or 'none'}); "
                              f"failed {len(failed)} ({', '.join(failed) or 'none'}).")
            if failed:
                self._install_log("Failed items usually mean: not running as "
                                  "Administrator, no winget/choco, or no network. "
                                  "Fix that and retry, or use the copied command.")
            self.event_q.put(("install_done", None))
        self._run_bg(work)
        self.status.set("Installing… watch the output box (admin prompts may appear).")

    def _install_selected(self):
        sel = self.tools_tree.selection()
        keys = [self._tool_iid_key.get(i) for i in sel]
        keys = [k for k in keys if k and not tools_reg.REGISTRY_BY_KEY[k].installed()]
        if sel and not keys:
            messagebox.showinfo("Install", "That tool is already installed.")
            return
        self._run_installs(keys)

    def _install_all_missing(self):
        # Skip optional tools (masscan/dig/nikto on Windows) — install them only
        # when explicitly selected.
        keys = [r["key"] for r in tools_reg.detect_all()
                if not r["installed"] and r.get("can_auto") and not r.get("optional")]
        if not keys:
            messagebox.showinfo(
                "Install", "No tools can be auto-installed here (no package manager, "
                "or the rest need manual download). Double-click a tool to copy its "
                "install command.")
            return
        if not messagebox.askyesno(
                "Install all missing",
                f"AyaRecon will install {len(keys)} tool(s) via your package manager. "
                "You may see admin/UAC prompts. Continue?"):
            return
        self._run_installs(keys)

    def _pip_install(self):
        if self._installing:
            return
        self._installing = True
        self.status.set("Installing Python libraries…")

        def work():
            self._install_log("\n=== pip install -r requirements.txt ===")
            tools_reg.pip_install_requirements(on_line=self._install_log)
            self.event_q.put(("install_done", None))
        self._run_bg(work)

    # ===================================================================== AI
    def _build_ai(self):
        f = self.tab_ai
        ttk.Label(f, text="AI Assistant", style="Head.TLabel").pack(anchor="w", padx=16, pady=(14, 2))
        self.ai_status = tk.StringVar()
        tk.Label(f, textvariable=self.ai_status, bg=BG, fg=MUTED,
                 wraplength=960, justify="left").pack(anchor="w", padx=16)

        # AI setup toolbar — makes the chat "work" by connecting a local model.
        setup = tk.Frame(f, bg=BG)
        setup.pack(fill="x", padx=16, pady=(6, 2))
        ttk.Button(setup, text="Test AI connection",
                   command=self._refresh_ai_status).pack(side="left")
        ttk.Button(setup, text="Install Ollama",
                   command=self._install_ollama).pack(side="left", padx=6)
        tk.Label(setup, text="Model:", bg=BG, fg=FG).pack(side="left", padx=(8, 2))
        self.ai_model_entry = ttk.Entry(setup, width=14)
        self.ai_model_entry.insert(0, self.config.get("ollama_model", "llama3"))
        self.ai_model_entry.pack(side="left")
        ttk.Button(setup, text="Pull model",
                   command=self._pull_model).pack(side="left", padx=6)
        ttk.Button(setup, text="🗑 Clear chat", style="Ghost.TButton",
                   command=self._ai_clear).pack(side="right")

        self.ai_log = scrolledtext.ScrolledText(f, height=18, bg="#181026", fg=FG,
                                                insertbackground=FG, wrap="word",
                                                relief="flat", padx=10, pady=8)
        self.ai_log.pack(fill="both", expand=True, padx=16, pady=8)
        # Speech-bubble tags: user (lavender, right), AyaRecon (teal-green, left).
        self.ai_log.tag_configure("you_name", foreground=ACCENT2,
                                  font=("Segoe UI", 9, "bold"),
                                  lmargin1=140, lmargin2=140, spacing1=8)
        self.ai_log.tag_configure("you_msg", background="#39236b", foreground="#f3ecff",
                                  lmargin1=140, lmargin2=140, rmargin=6,
                                  spacing1=2, spacing3=8, borderwidth=6, relief="flat")
        self.ai_log.tag_configure("bot_name", foreground="#7fe3c0",
                                  font=("Segoe UI", 9, "bold"),
                                  lmargin1=6, lmargin2=6, spacing1=8)
        self.ai_log.tag_configure("bot_msg", background="#241a38", foreground=FG,
                                  lmargin1=6, lmargin2=6, rmargin=140,
                                  spacing1=2, spacing3=8, borderwidth=6, relief="flat")
        self.ai_log.tag_configure("sys_msg", foreground=MUTED,
                                  font=("Segoe UI", 9, "italic"),
                                  lmargin1=6, lmargin2=6, spacing1=4)
        self.ai_log.configure(state="disabled")
        self._ai_bubble("sys", "AyaRecon AI ready. The offline analyst works now; connect "
                        "Ollama above for full chat. Try “show me all critical findings” "
                        "or “how can this be hacked?”")

        row = tk.Frame(f, bg=BG)
        row.pack(fill="x", padx=16, pady=(0, 14))
        self.ai_entry = ttk.Entry(row)
        self.ai_entry.pack(side="left", fill="x", expand=True)
        self.ai_entry.bind("<Return>", lambda e: self._ask_ai())
        ttk.Button(row, text="Ask", command=self._ask_ai).pack(side="left", padx=8)
        ttk.Button(row, text="Correlate risks", command=self._correlate).pack(side="left")
        self.ai_status.set("Checking AI status…")
        self._refresh_ai_status()

    def _ai_bubble(self, sender, text):
        self.ai_log.configure(state="normal")
        if sender == "you":
            self.ai_log.insert("end", "You\n", ("you_name",))
            self.ai_log.insert("end", text + "\n", ("you_msg",))
        elif sender == "sys":
            self.ai_log.insert("end", text + "\n", ("sys_msg",))
        else:
            self.ai_log.insert("end", "🛡 AyaRecon\n", ("bot_name",))
            self.ai_log.insert("end", text + "\n", ("bot_msg",))
        self.ai_log.see("end")
        self.ai_log.configure(state="disabled")

    def _ai_clear(self):
        self.ai_log.configure(state="normal")
        self.ai_log.delete("1.0", "end")
        self.ai_log.configure(state="disabled")
        self._ai_bubble("sys", "Chat cleared.")

    def _refresh_ai_status(self):
        # Rebuild the engine (picks up just-installed libs/config), then show a
        # plain-English diagnosis — in the background, since the Ollama check does
        # a network call.
        self.ai_status.set("Checking AI status…")

        def work():
            self.ai = AIEngine(self.config)
            self.scanner.ai = self.ai
            try:
                diag = self.ai.ai_diagnosis()
            except Exception as exc:
                diag = f"AI status check failed: {exc}"
            self.event_q.put(("ai_status", diag))
        self._run_bg(work)

    def _install_ollama(self):
        if getattr(self, "_installing", False):
            messagebox.showinfo("Busy", "An install is already running (see Tools tab).")
            return
        self.nb.select(self.tab_tools)
        self._run_installs(["ollama"])

    def _pull_model(self):
        model = self.ai_model_entry.get().strip() or "llama3"
        self.config.set("ollama_model", model)
        self.config.save()
        self._ai_bubble("sys", f"Pulling model '{model}' … (first time downloads a few GB; "
                        "watch the Tools tab output)")
        self.nb.select(self.tab_tools)

        def work():
            self.ai.pull_model(model, on_line=lambda l: self.event_q.put(("install_log", l)))
            self.event_q.put(("install_done", None))
            self.event_q.put(("ai", f"Model '{model}' pull finished — click "
                              "'Test AI connection' on the AI tab."))
        self._run_bg(work)

    def _ask_ai(self):
        q = self.ai_entry.get().strip()
        if not q:
            return
        self.ai_entry.delete(0, "end")
        self._ai_bubble("you", q)
        findings = self.db.list_findings(self.workspace_id)

        def work():
            try:
                ans = self.ai.ask(q, findings) or "(no answer produced)"
            except Exception as exc:
                ans = (f"[AI error] {exc}\nThe offline analyst should still work — "
                       "if this persists, check the AI tab status/Ollama.")
            self.event_q.put(("ai", ans))
        self._run_bg(work)

    def _correlate(self):
        findings = self.db.list_findings(self.workspace_id)
        insights = self.ai.correlate(findings)
        self._ai_bubble("bot", "Correlation analysis:\n" +
                        "\n".join(f"• {i}" for i in insights))

    # ===================================================================== reports
    def _build_reports(self):
        f = self.tab_rep
        ttk.Label(f, text="Reports & export", style="Head.TLabel").pack(anchor="w", padx=16, pady=(14, 4))
        tk.Label(f, text="Auto-generates three documents and exports in your chosen format.",
                 bg=BG, fg=MUTED).pack(anchor="w", padx=16)

        row = tk.Frame(f, bg=BG)
        row.pack(fill="x", padx=16, pady=10)
        for label, kind in [("Executive summary", "exec"),
                            ("Technical report", "tech"),
                            ("Remediation roadmap", "road")]:
            ttk.Button(row, text=label,
                       command=lambda k=kind: self._show_doc(k)).pack(side="left", padx=5)

        row2 = tk.Frame(f, bg=BG)
        row2.pack(fill="x", padx=16, pady=4)
        tk.Label(row2, text="Export:", bg=BG, fg=FG).pack(side="left")
        for fmt in ["HTML", "PDF", "CSV", "JSON"]:
            ttk.Button(row2, text=fmt,
                       command=lambda x=fmt: self._export(x)).pack(side="left", padx=4)

        self.report_box = scrolledtext.ScrolledText(f, bg="#0c0e14", fg=FG, wrap="word",
                                                    relief="flat", insertbackground=FG)
        self.report_box.pack(fill="both", expand=True, padx=16, pady=12)

    def _findings_for_report(self):
        return self.db.list_findings(self.workspace_id)

    def _show_doc(self, kind):
        findings = self._findings_for_report()
        counts = self.db.severity_counts(self.workspace_id)
        summary = self.ai.executive_summary(findings, counts)
        if kind == "exec":
            text = reports.executive_summary_doc(findings, counts, summary, self.workspace_name)
        elif kind == "tech":
            text = reports.technical_report_doc(findings, self.workspace_name)
        else:
            text = reports.remediation_roadmap_doc(findings, self.workspace_name)
        self.report_box.delete("1.0", "end")
        self.report_box.insert("end", text)

    def _export(self, fmt):
        findings = self._findings_for_report()
        if not findings:
            messagebox.showinfo("Export", "No findings to export yet.")
            return
        counts = self.db.severity_counts(self.workspace_id)
        summary = self.ai.executive_summary(findings, counts)
        ext = {"HTML": ".html", "PDF": ".pdf", "CSV": ".csv", "JSON": ".json"}[fmt]
        path = filedialog.asksaveasfilename(defaultextension=ext,
                                            initialfile=f"aya_report{ext}")
        if not path:
            return
        try:
            if fmt == "HTML":
                reports.export_html(findings, path, counts, summary, self.workspace_name)
            elif fmt == "PDF":
                reports.export_pdf(findings, path, counts, summary, self.workspace_name)
            elif fmt == "CSV":
                reports.export_csv(findings, path)
            else:
                reports.export_json(findings, path)
            self.status.set(f"Exported {fmt} -> {path}")
            messagebox.showinfo("Export", f"Saved {fmt} report to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    # ===================================================================== settings
    def _build_settings(self):
        f = self.tab_set
        ttk.Label(f, text="Settings", style="Head.TLabel").pack(anchor="w", padx=16, pady=(14, 6))
        grid = tk.Frame(f, bg=BG)
        grid.pack(fill="x", padx=16)

        self.set_vars = {}
        fields = [
            ("AI provider", "ai_provider", "combo", ["ollama", "openai", "anthropic", "none"]),
            ("Ollama host", "ollama_host", "entry", None),
            ("Ollama model", "ollama_model", "entry", None),
            ("Cloud API key", "cloud_api_key", "entry", None),
            ("Cloud model", "cloud_model", "entry", None),
            ("HIBP API key", "hibp_api_key", "entry", None),
            ("GitHub token", "github_token", "entry", None),
            ("NVD API key (live CVEs)", "nvd_api_key", "entry", None),
            ("Custom wordlist path", "custom_wordlist_path", "entry", None),
            ("TCP timeout (s)", "tcp_timeout", "entry", None),
            ("HTTP timeout (s)", "http_timeout", "entry", None),
            ("Max threads", "max_threads", "entry", None),
            ("Rate limit (req/s)", "rate_limit_per_sec", "entry", None),
        ]
        for i, (label, key, kind, choices) in enumerate(fields):
            tk.Label(grid, text=label, bg=BG, fg=FG, width=22, anchor="w").grid(
                row=i, column=0, sticky="w", pady=3)
            if kind == "combo":
                var = tk.StringVar(value=str(self.config.get(key)))
                w = ttk.Combobox(grid, textvariable=var, values=choices, width=40)
            else:
                var = tk.StringVar(value=str(self.config.get(key)))
                show = "*" if "key" in key or "token" in key else ""
                w = ttk.Entry(grid, textvariable=var, width=43, show=show)
            w.grid(row=i, column=1, sticky="w", padx=8, pady=3)
            self.set_vars[key] = var

        brow = tk.Frame(f, bg=BG)
        brow.pack(fill="x", padx=16, pady=12)
        ttk.Button(brow, text="Save settings", command=self._save_settings).pack(side="left")
        ttk.Button(brow, text="Open wordlist folder",
                   command=lambda: self._open_path(WORDLIST_DIR)).pack(side="left", padx=8)
        ttk.Button(brow, text="View permission audit log",
                   command=self._show_audit).pack(side="left")

        # owned assets
        ttk.Label(f, text="Owned assets (defensive mode allowlist)",
                  style="Head.TLabel").pack(anchor="w", padx=16, pady=(8, 2))
        self.owned_box = tk.Listbox(f, bg="#0c0e14", fg=FG, height=5, relief="flat")
        self.owned_box.pack(fill="x", padx=16)
        self._refresh_owned()

    def _save_settings(self):
        for key, var in self.set_vars.items():
            val = var.get()
            if key in ("tcp_timeout", "http_timeout", "rate_limit_per_sec"):
                val = float(val) if val else 0
            elif key in ("max_threads",):
                val = int(float(val)) if val else 1
            self.config.set(key, val)
        self.config.save()
        self.ai = AIEngine(self.config)
        self.scanner.ai = self.ai
        self._refresh_ai_status()
        self.status.set("Settings saved.")
        messagebox.showinfo("Settings", "Saved. Made by Ruel.")

    def _mark_owned(self):
        t = self.def_target.get().strip().lower()
        if not t:
            return
        owned = self.config.get("owned_assets", [])
        if t not in owned:
            owned.append(t)
            self.config.set("owned_assets", owned)
            self.config.save()
        self._refresh_owned()
        self.status.set(f"Marked '{t}' as an owned asset.")

    def _refresh_owned(self):
        if not hasattr(self, "owned_box"):
            return
        self.owned_box.delete(0, "end")
        for a in self.config.get("owned_assets", []):
            self.owned_box.insert("end", a)

    def _show_audit(self):
        rows = self.db.list_permission_log()
        win = tk.Toplevel(self.root, bg=BG)
        win.title("Permission audit log — AyaRecon by Ruel")
        win.geometry("760x420")
        box = scrolledtext.ScrolledText(win, bg="#0c0e14", fg=FG, wrap="none")
        box.pack(fill="both", expand=True)
        if not rows:
            box.insert("end", "No permission events logged yet.")
        for r in rows:
            box.insert("end", f"{r['timestamp']}  [{r['mode']}]  {r['module']}  -> "
                              f"{r['target']}  confirmed={bool(r['confirmed'])}\n")
        box.configure(state="disabled")

    # ===================================================================== launch
    def _launch(self, mode, module):
        target_widget = self.def_target if mode == "defensive" else self.recon_target
        target = target_widget.get().strip()
        if not target:
            messagebox.showwarning("Target required", "Enter a target first.")
            return

        confirmed = True
        conf_text = ""
        if mode == "active":
            confirmed = messagebox.askyesno(
                "Confirm active scan",
                f"Active scanning sends packets to {target} and may be logged.\n\n"
                "Do you have authorisation to scan this target?")
            conf_text = "user confirmed active scan"
            if not confirmed:
                return
        elif mode == "enumeration":
            if not getattr(self, "enable_bruteforce", None) or not self.enable_bruteforce.get():
                messagebox.showerror(
                    "Disabled", "Tick the 'I have written permission' box to enable "
                    "this section first.")
                return
            if not self.perms.enumeration_unlocked:
                messagebox.showerror("Locked", "Unlock the permission gate first.")
                return
            confirmed = messagebox.askyesno(
                "Confirm enumeration",
                f"Enumeration against {target} is noisy and may be treated as an "
                "attack.\n\nConfirm you have WRITTEN PERMISSION to test this target?")
            conf_text = "user confirmed enumeration with permission"
            if not confirmed:
                return
        elif mode == "defensive":
            if not self.config.is_owned(target):
                confirmed = messagebox.askyesno(
                    "Confirm ownership",
                    f"'{target}' is not in your owned-assets list.\n\n"
                    "Do you confirm you own or are authorised to audit it?")
                conf_text = "user confirmed ownership"
                if not confirmed:
                    return

        tree = {"passive": self.recon_tree, "active": self.recon_tree,
                "enumeration": self.recon_tree, "defensive": self.def_tree}[mode]
        self.status.set(f"Running {module} against {target} …")
        self.recon_prog.configure(value=0, maximum=100)

        def progress(done, total):
            self.event_q.put(("progress", (done, total)))

        def work():
            decision, findings = self.scanner.run(
                self.workspace_id, target, mode, module,
                confirmed=confirmed, confirmation_text=conf_text, progress=progress)
            self.event_q.put(("scan_done", (mode, tree, decision, findings)))

        self._run_bg(work)

    def _unlock_gate(self):
        messagebox.showwarning("Legal warning", LEGAL_WARNING)
        phrase = simpledialog.askstring(
            "Unlock enumeration",
            f'Type exactly "{PERMISSION_PHRASE}" to confirm you have authorisation:')
        if phrase and self.perms.unlock_enumeration(phrase):
            self.status.set("Enumeration unlocked for this session.")
            messagebox.showinfo("Unlocked", "Enumeration modules enabled. Use responsibly.")
        else:
            messagebox.showerror("Not unlocked", "Phrase did not match. Still locked.")
        self._update_gate_label()

    def _update_gate_label(self):
        if self.perms.enumeration_unlocked:
            self.gate_var.set("⚠ Enumeration UNLOCKED")
        else:
            self.gate_var.set("🔒 Enumeration locked")

    # ===================================================================== queue pump
    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.event_q.get_nowait()
                if kind == "progress":
                    done, total = payload
                    self.recon_prog.configure(maximum=total, value=done)
                    self.status.set(f"Progress: {done}/{total}")
                elif kind == "phase":
                    self.phase_var.set("▶ " + payload)
                    self.status.set(payload)
                elif kind == "packet":
                    self._cap_add_packet(payload)
                elif kind == "cap_detail":
                    self._cap_detail_set(payload)
                elif kind == "cap_filtered":
                    self._cap_show_rows(payload)
                elif kind == "cap_done":
                    self._capture_session = None
                    self.status.set(payload)
                    if hasattr(self, "cap_status"):
                        self.cap_status.set(payload + "  " + capture_mod.backend_help())
                elif kind == "term":
                    self._term_write(payload)
                elif kind == "term_done":
                    self._term_write("\n")
                elif kind == "install_log":
                    self.tools_log.insert("end", payload + "\n")
                    self.tools_log.see("end")
                elif kind == "install_done":
                    self._installing = False
                    self._refresh_tools()
                    self._refresh_ai_status()
                    self.status.set("Install step finished — re-checked tools.")
                elif kind == "ai":
                    self._ai_bubble("bot", payload)
                elif kind == "busy":
                    self._busy_delta(payload)
                elif kind == "ai_status":
                    self.ai_status.set(payload)
                elif kind == "tools_rows":
                    self._fill_tools(payload)
                elif kind == "cap_ifaces":
                    self.cap_iface.configure(values=payload)
                    if payload and not self.cap_iface.get():
                        self.cap_iface.current(0)
                    self.cap_status.set(capture_mod.backend_help())
                elif kind == "scan_done":
                    mode, tree, decision, findings = payload
                    if not decision.allowed:
                        self.status.set("Blocked: " + decision.reason)
                        messagebox.showwarning("Not permitted", decision.reason)
                    else:
                        self._fill_tree(tree, findings)
                        self.status.set(f"Done — {len(findings)} findings.")
                        self.recon_prog.configure(value=0)
                        self.refresh_dashboard()
                        if mode == "defensive":
                            counts = self.db.severity_counts(self.workspace_id)
                            g = defensive.grade(counts)
                            self.def_grade.set(f"Grade: {g['grade']} ({g['score']}/100)")
                    self._update_gate_label()
        except queue.Empty:
            pass
        self.root.after(150, self._drain_queue)

    # ===================================================================== tree helpers
    def _make_tree(self, parent, cols):
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=12)
        widths = {"severity": 90, "category": 110, "title": 240, "detail": 520}
        for c in cols:
            tree.heading(c, text=c.capitalize())
            tree.column(c, width=widths.get(c, 160), anchor="w")
        for sev, col in SEV_COLORS.items():
            tree.tag_configure(sev, foreground=col)
        # Click a finding to open its detail + attack/remediation briefing.
        tree.bind("<Double-1>", self._on_finding_click)
        tree.bind("<Return>", self._on_finding_click)
        if not hasattr(self, "_tree_findings"):
            self._tree_findings = {}
        return tree

    def _fill_tree(self, tree, findings):
        tree.delete(*tree.get_children())
        if not hasattr(self, "_tree_findings"):
            self._tree_findings = {}
        self._tree_findings[str(tree)] = {}
        for f in findings:
            sev = f.get("severity", "info")
            iid = tree.insert("", "end", tags=(sev,), values=(
                sev.upper(), f.get("category", ""), f.get("title", ""),
                (f.get("detail", "") or "")[:300]))
            self._tree_findings[str(tree)][iid] = f

    def _on_finding_click(self, event):
        tree = event.widget
        sel = tree.selection()
        if not sel:
            return
        finding = self._tree_findings.get(str(tree), {}).get(sel[0])
        if finding:
            self._show_finding_detail(finding)

    def _show_finding_detail(self, finding):
        win = tk.Toplevel(self.root, bg=BG)
        sev = finding.get("severity", "info")
        win.title(f"Finding — {finding.get('title','')}")
        win.geometry("720x620")

        head = tk.Frame(win, bg=PANEL)
        head.pack(fill="x")
        tk.Label(head, text=finding.get("title", ""), bg=PANEL, fg=FG,
                 font=("Segoe UI", 14, "bold"), wraplength=680, justify="left",
                 anchor="w").pack(fill="x", padx=16, pady=(12, 2))
        tk.Label(head, text=f"{sev.upper()}  ·  {finding.get('category','')}  ·  "
                            f"{finding.get('target','')}", bg=PANEL,
                 fg=SEV_COLORS.get(sev, MUTED), font=("Segoe UI", 10, "bold"),
                 anchor="w").pack(fill="x", padx=16, pady=(0, 12))

        body = scrolledtext.ScrolledText(win, bg="#0c0e14", fg=FG, wrap="word",
                                         relief="flat", font=("Segoe UI", 10),
                                         insertbackground=FG)
        body.pack(fill="both", expand=True, padx=14, pady=10)

        def section(title, text):
            body.insert("end", title + "\n", ("h",))
            body.insert("end", (text or "—") + "\n\n")

        body.tag_configure("h", foreground=ACCENT, font=("Segoe UI", 11, "bold"))

        section("Detail", finding.get("detail", ""))
        data = finding.get("data", {}) or {}
        if data:
            kv = "\n".join(f"  {k}: {v}" for k, v in data.items()
                           if k not in ("records",) and not isinstance(v, (list, dict)))
            if kv:
                section("Data", kv)

        # Use the offline briefing directly so the window opens instantly (the
        # LLM elaboration is behind the 'Ask AI about this' button).
        b = exploitation.brief_for_finding(finding)
        if b:
            section("Attack path, impact & remediation", b.as_text())
        else:
            section("Remediation", finding.get("remediation")
                    or "Review this item against vendor guidance.")

        if finding.get("ai_reasoning"):
            section("Analyst note", finding["ai_reasoning"])

        body.configure(state="disabled")

        btns = tk.Frame(win, bg=BG)
        btns.pack(fill="x", padx=14, pady=(0, 12))
        ttk.Button(btns, text="🤖 Ask AI about this",
                   command=lambda: self._ask_ai_about(finding, win)).pack(side="left")
        ttk.Button(btns, text="Copy remediation",
                   command=lambda: self._copy_text(finding.get("remediation", ""))
                   ).pack(side="left", padx=8)
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")

    def _ask_ai_about(self, finding, win=None):
        if win:
            win.destroy()
        self.nb.select(self.tab_ai)
        q = f"Explain the attack path and remediation for: {finding.get('title')} " \
            f"({finding.get('detail','')})"
        self._ai_bubble("you", q)
        findings = [finding]

        def work():
            ans = self.ai.explain_finding(finding)
            self.event_q.put(("ai", ans))
        self._run_bg(work)

    def _copy_text(self, text):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text or "")
            self.status.set("Copied to clipboard.")
        except Exception:
            pass

    def _open_path(self, path):
        import os, subprocess, sys
        path = str(path)
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # noqa
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            messagebox.showinfo("Path", path)


def launch():
    root = tk.Tk()
    try:
        AyaReconApp(root)
    except SystemExit:
        return
    root.mainloop()

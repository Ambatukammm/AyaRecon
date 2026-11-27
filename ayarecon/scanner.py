"""
AyaRecon — orchestrator.
Made by Ruel.

Ties everything together: given a target, a mode and a module, it
  1. asks the PermissionManager whether it may run,
  2. runs the module,
  3. runs AI scoring over the results,
  4. persists findings to the workspace database,
  5. returns the findings (already scored) to the caller.

The GUI and any CLI both go through this single choke-point, which guarantees
that nothing can bypass the permission + audit layer.
"""

from __future__ import annotations

from typing import Callable

from .config import Config
from .db import Database
from .permissions import PermissionManager, Mode, Decision
from .ai.engine import AIEngine
from .modules import (
    passive, active, recon_enum, defensive, enumeration, vuln_assessment,
    network_discovery,
)
from .integrations import nmap_tool
from .util import normalise_target, TOP_100_PORTS


class Scanner:
    def __init__(self, config: Config, db: Database, perms: PermissionManager,
                 ai: AIEngine):
        self.config = config
        self.db = db
        self.perms = perms
        self.ai = ai

    # ------------------------------------------------------------------- run
    def run(
        self,
        workspace_id: int,
        target: str,
        mode: str,
        module: str,
        confirmed: bool = False,
        confirmation_text: str = "",
        progress: Callable[[int, int], None] | None = None,
        on_finding: Callable[[dict], None] | None = None,
        **kwargs,
    ) -> tuple[Decision, list[dict]]:
        target = normalise_target(target)
        mode_enum = Mode(mode)

        decision = self.perms.check(
            mode_enum, target, module, confirmed=confirmed,
            workspace_id=workspace_id, confirmation_text=confirmation_text,
        )
        if not decision.allowed:
            return decision, []

        scan_id = self.db.start_scan(workspace_id, target, module, mode)
        try:
            # workspace_id is passed through so analysis-only modules (Phase 4)
            # can read the findings already gathered in this workspace.
            kwargs.setdefault("workspace_id", workspace_id)
            raw = self._dispatch(target, module, progress=progress, **kwargs)
            scored = self.ai.analyse(raw)
            for f in scored:
                self.db.add_finding(
                    workspace_id=workspace_id,
                    target=target,
                    category=f.get("category", "misc"),
                    title=f.get("title", ""),
                    detail=f.get("detail", ""),
                    data=f.get("data", {}),
                    severity=f.get("severity", "info"),
                    scan_id=scan_id,
                    ai_reasoning=f.get("ai_reasoning", ""),
                    remediation=f.get("remediation", ""),
                )
                f["target"] = target
                if on_finding:          # stream each finding to the UI as it lands
                    try:
                        on_finding(f)
                    except Exception:
                        pass
            self.db.finish_scan(scan_id, "done")
            return decision, scored
        except Exception as exc:
            self.db.finish_scan(scan_id, f"error: {exc}")
            return Decision(False, f"Scan error: {exc}"), []

    # ------------------------------------------------------------ full workflow
    def run_full_workflow(
        self,
        workspace_id: int,
        target: str,
        confirmed: bool,
        phase_cb: Callable[[str], None] | None = None,
        on_finding: Callable[[dict], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[Decision, list[dict]]:
        """
        Run phases 1→4 in sequence (AI/reporting is phase 5, done on demand):
          1 passive recon → 2 port scan → 3 service enumeration → 4 vuln assess.
        Phases 2 and 3 make direct contact and require `confirmed=True`.
        """
        if not confirmed:
            return Decision(False, "Full workflow includes active phases — "
                            "confirmation required."), []
        collected: list[dict] = []

        def step(label, mode, module, **kw):
            if cancel_check and cancel_check():
                return
            if phase_cb:
                phase_cb(label)
            dec, found = self.run(workspace_id, target, mode, module,
                                  confirmed=confirmed, on_finding=on_finding,
                                  confirmation_text="full workflow", **kw)
            collected.extend(found)

        step("VLAN/VPN analysis", "passive", "network.vlanvpn")
        step("Phase 1 — Passive reconnaissance", "passive", "passive.all")
        step("Phase 2 — Port & service scanning", "active", "active.portscan")
        step("Phase 3 — Service enumeration", "active", "enumeration.all")
        step("Phase 3 — HTTP fingerprint/headers", "active", "active.http")
        step("Phase 4 — Vulnerability assessment", "passive", "vuln.assess")
        if phase_cb:
            phase_cb("Workflow complete")
        return Decision(True, "Full 5-phase workflow complete (phase 5 = reports)."), collected

    # ------------------------------------------------------------------- dispatch
    def _dispatch(self, target, module, progress=None, **kwargs) -> list[dict]:
        rate = float(self.config.get("rate_limit_per_sec", 20))
        threads = int(self.config.get("max_threads", 50))
        http_to = float(self.config.get("http_timeout", 8))
        tcp_to = float(self.config.get("tcp_timeout", 1))

        # --- passive ---
        if module == "passive.dns":
            return passive.dns_records(target, timeout=float(self.config.get("dns_timeout", 5)))
        if module == "passive.reverse_dns":
            return passive.reverse_dns(target)
        if module == "passive.whois":
            return passive.whois_lookup(target)
        if module == "passive.ssl":
            return passive.ssl_certificate(target, timeout=http_to)
        if module == "passive.subdomains":
            return passive.subdomains_crtsh(target)
        if module == "passive.wayback":
            return passive.wayback_snapshots(target)
        if module == "passive.breach":
            return passive.breach_lookup(kwargs.get("email", target),
                                         api_key=self.config.get("hibp_api_key", ""))
        if module == "passive.all":
            out = []
            for fn in (passive.dns_records, passive.reverse_dns, passive.whois_lookup,
                       passive.ssl_certificate, passive.subdomains_crtsh):
                out += fn(target)
            return out

        # --- active ---
        if module == "active.ping":
            return active.ping_host(target, timeout=tcp_to)
        if module == "active.portscan":
            ports = kwargs.get("ports") or TOP_100_PORTS
            return active.port_scan(target, ports=ports, timeout=tcp_to, max_threads=threads)
        if module == "active.http":
            return active.http_fingerprint(target, timeout=http_to)

        # --- enumeration (gated) ---
        if module == "enum.directories":
            wl = recon_enum.load_wordlist(
                self.config.get("custom_wordlist_path"), recon_enum.BUILTIN_DIR_WORDS)
            return recon_enum.directory_enum(target, wordlist=wl, rate_per_sec=rate,
                                             timeout=http_to, progress=progress)
        if module == "enum.subdomains":
            wl = recon_enum.load_wordlist(
                self.config.get("custom_wordlist_path"), recon_enum.BUILTIN_SUBDOMAIN_WORDS)
            return recon_enum.subdomain_enum(target, wordlist=wl, rate_per_sec=rate,
                                             progress=progress)

        # --- phase 3: service enumeration (per protocol) ---
        if module.startswith("enumeration."):
            proto = module.split(".", 1)[1].upper()
            fn = enumeration.ENUM_PROTOCOLS.get(proto)
            if fn:
                return fn(target)
            raise ValueError(f"Unknown enumeration protocol: {proto}")
        if module == "enumeration.all":
            out = []
            for name, fn in enumeration.ENUM_PROTOCOLS.items():
                out += fn(target)
            return out

        # --- nmap integration (Phase 2 power option; direct contact) ---
        if module == "nmap.scan":
            findings, cmd = nmap_tool.run(
                target, args=kwargs.get("nmap_args"),
                preset=kwargs.get("preset"))
            # Record the exact nmap command line in the audit trail.
            if cmd:
                self.db.log_permission(
                    kwargs.get("workspace_id"), target, f"nmap: {cmd}",
                    "active", True, "nmap scan")
            return findings

        # --- VLAN / VPN analysis (local config + routing; no traffic) ---
        if module == "network.vlanvpn":
            return network_discovery.vlan_vpn_report(kwargs.get("vlan_ids"))

        # --- phase 4: vulnerability assessment (analysis only, no network) ---
        if module == "vuln.assess":
            existing = self.db.list_findings(kwargs["workspace_id"]) \
                if kwargs.get("workspace_id") else kwargs.get("findings", [])
            return vuln_assessment.assess(existing)

        # --- defensive ---
        if module == "defensive.self_audit":
            return defensive.self_audit(target, include_active=kwargs.get("include_active", True))
        if module == "defensive.privacy":
            return defensive.privacy_footprint(
                target, emails=kwargs.get("emails", []),
                hibp_key=self.config.get("hibp_api_key", ""))

        raise ValueError(f"Unknown module: {module}")

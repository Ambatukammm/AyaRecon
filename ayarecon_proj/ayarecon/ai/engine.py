"""
AyaRecon — PART 5: AI Intelligence Engine.
Made by Ruel.

The engine has two layers:

  1. A deterministic rule-based analyst that ALWAYS works offline. It scores
     every finding, explains what it means, correlates findings, and produces
     remediation steps. No model required.

  2. An optional LLM layer (local Ollama by default, or a cloud API key) that
     can summarise reports and answer free-form questions about the local
     findings. If no model is available, the engine falls back to the
     rule-based summaries so the app never breaks.

The conversational assistant queries ONLY the local database — your data never
leaves the device unless you explicitly configure a cloud provider.
"""

from __future__ import annotations

import json
from typing import Any

from ..modules import exploitation

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


# --------------------------------------------------------------------------- rules
# (pattern -> (severity, explanation, remediation))
RULES: list[dict[str, Any]] = [
    {
        "match": lambda f: f["category"] == "port" and f.get("data", {}).get("port") == 3389,
        "severity": "critical",
        "why": "RDP (3389) is exposed to the internet. Attackers continuously "
               "scan for and brute-force RDP; it is a top ransomware entry point.",
        "fix": "Restrict 3389 to a VPN or specific IPs via firewall, enable "
               "Network Level Authentication, or disable RDP if unused.",
    },
    {
        "match": lambda f: f["category"] == "port" and f.get("data", {}).get("port") == 23,
        "severity": "critical",
        "why": "Telnet (23) transmits credentials in clear text and is obsolete.",
        "fix": "Disable Telnet entirely and use SSH instead.",
    },
    {
        "match": lambda f: f["category"] == "port" and f.get("data", {}).get("port") in (445, 139, 135),
        "severity": "high",
        "why": "SMB/NetBIOS exposed to the internet is routinely exploited "
               "(e.g. EternalBlue-class bugs, credential relay).",
        "fix": "Block 135/139/445 at the perimeter firewall; never expose SMB publicly.",
    },
    {
        "match": lambda f: f["category"] == "port" and f.get("data", {}).get("port") in (6379, 27017, 9200, 11211),
        "severity": "critical",
        "why": "A database/cache service is exposed. These often ship with no "
               "authentication by default and lead to full data exposure.",
        "fix": "Bind the service to localhost or a private network, require "
               "authentication, and firewall the port.",
    },
    {
        "match": lambda f: f["category"] == "port" and f.get("data", {}).get("port") in (3306, 5432, 1433),
        "severity": "high",
        "why": "A database server is reachable from the internet, widening the "
               "attack surface for brute-force and exploitation.",
        "fix": "Restrict the DB port to application servers only; never expose publicly.",
    },
    {
        "match": lambda f: f["category"] == "header" and f.get("data", {}).get("missing")
                 and f.get("data", {}).get("header") == "HSTS",
        "severity": "medium",
        "why": "No HSTS header: browsers can be downgraded to HTTP, enabling "
               "man-in-the-middle attacks.",
        "fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    },
    {
        "match": lambda f: f["category"] == "header" and f.get("data", {}).get("missing")
                 and f.get("data", {}).get("header") == "Content-Security-Policy",
        "severity": "medium",
        "why": "No Content-Security-Policy: raises the risk and impact of XSS.",
        "fix": "Define a CSP that restricts script/style/src origins to trusted hosts.",
    },
    {
        "match": lambda f: f["category"] == "ssl" and "EXPIRED" in (f.get("detail") or ""),
        "severity": "high",
        "why": "The TLS certificate has expired; clients will see errors and "
               "connections are no longer trustworthy.",
        "fix": "Renew the certificate immediately and automate renewal (e.g. ACME).",
    },
    {
        "match": lambda f: f["category"] == "breach",
        "severity": "high",
        "why": "This account appears in a known data breach, so its password "
               "(and any reused elsewhere) should be considered compromised.",
        "fix": "Reset the password everywhere it was used and enable MFA.",
    },
    {
        "match": lambda f: f["category"] == "enum" and f.get("severity") == "high",
        "severity": "high",
        "why": "A sensitive path (e.g. .git, .env, backups, config) is reachable. "
               "These frequently leak source code, credentials or secrets.",
        "fix": "Remove the file from the web root or block it at the server; rotate "
               "any secrets that were exposed.",
    },
]


class AIEngine:
    def __init__(self, config):
        self.config = config

    # ----------------------------------------------------------------- scoring
    def score_finding(self, finding: dict) -> dict:
        """Return {severity, reasoning, remediation} for a single finding."""
        for rule in RULES:
            try:
                if rule["match"](finding):
                    return {
                        "severity": rule["severity"],
                        "reasoning": rule["why"],
                        "remediation": rule["fix"],
                    }
            except Exception:
                continue
        # Default: keep whatever the module already decided. Crucially, PRESERVE
        # any reasoning/remediation the finding already carries (Phase 4 vuln
        # findings arrive pre-populated) instead of blanking it.
        return {
            "severity": finding.get("severity", "info"),
            "reasoning": finding.get("ai_reasoning", ""),
            "remediation": finding.get("remediation", ""),
        }

    def analyse(self, findings: list[dict]) -> list[dict]:
        """Attach AI scoring to a list of findings (in place-ish, returns copy)."""
        out = []
        for f in findings:
            score = self.score_finding(f)
            g = dict(f)
            g["severity"] = score["severity"]
            g["ai_reasoning"] = score["reasoning"]
            g["remediation"] = score["remediation"]
            out.append(g)
        return out

    # ------------------------------------------------------------- correlation
    def correlate(self, findings: list[dict]) -> list[str]:
        """Connect dots across findings into higher-level risk statements."""
        insights: list[str] = []
        cats = {}
        for f in findings:
            cats.setdefault(f["category"], []).append(f)

        has_breach = bool(cats.get("breach"))
        exposed_admin = [f for f in cats.get("enum", [])
                         if "admin" in (f.get("detail", "").lower())]
        risky_ports = [f for f in cats.get("port", []) if f.get("severity") in ("high", "critical")]

        if has_breach and exposed_admin:
            insights.append(
                "An account tied to this target appears in a breach AND an admin "
                "panel is publicly reachable — credential-reuse against that panel "
                "is a realistic, high-priority risk."
            )
        if risky_ports and any("rdp" in (f.get("detail", "").lower()) for f in risky_ports):
            insights.append(
                "Internet-facing RDP combined with other exposed services makes this "
                "host an attractive ransomware target. Prioritise locking RDP down."
            )
        missing_sec_headers = [f for f in cats.get("header", []) if f.get("data", {}).get("missing")]
        if len(missing_sec_headers) >= 3:
            insights.append(
                f"{len(missing_sec_headers)} security headers are missing — the web "
                "app has weak browser-side defences (clickjacking, XSS, downgrade)."
            )

        # Phase 4 correlations.
        vulns = cats.get("vuln", [])
        crit_vulns = [v for v in vulns if v.get("severity") == "critical"]
        if crit_vulns:
            names = ", ".join(sorted({v["title"].replace("[CVE] ", "").replace(
                "[MISCONFIG] ", "") for v in crit_vulns}))[:200]
            insights.append(
                f"Phase 4 flagged {len(crit_vulns)} critical issue(s) — fix first: {names}."
            )
        anon_services = [v for v in vulns if v.get("data", {}).get("misconfig") in
                         ("anonymous_ftp", "smb_null_session", "ldap_anonymous_bind")]
        if len(anon_services) >= 2:
            insights.append(
                "Multiple services allow unauthenticated access (anonymous FTP / SMB "
                "null session / anonymous LDAP) — an attacker can map the estate "
                "without a single credential. Lock these down together."
            )

        if not insights:
            insights.append("No cross-finding correlations stood out in this dataset.")
        return insights

    # ------------------------------------------------------- summaries (rule-based)
    def executive_summary(self, findings: list[dict], severity_counts: dict) -> str:
        """Plain-English summary a non-specialist can act on: posture, the single
        biggest risk, and the first few things to fix."""
        crit = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        med = severity_counts.get("medium", 0)
        total = sum(severity_counts.values())

        if crit:
            posture = ("Overall posture: AT RISK. There are issues an attacker could "
                       "use to take control or steal data, and they need attention now.")
        elif high:
            posture = ("Overall posture: NEEDS WORK. No immediate critical holes, but "
                       "serious weaknesses should be fixed soon.")
        elif med:
            posture = ("Overall posture: FAIR. Mostly hardening gaps rather than "
                       "break-in risks.")
        elif total:
            posture = "Overall posture: GOOD. Only low or informational items were found."
        else:
            posture = "Overall posture: nothing notable found yet — run the scans first."

        # Pick the top things to fix (highest severity first, with a real fix).
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranked = sorted(findings, key=lambda f: order.get(f.get("severity", "info"), 4))
        top = [f for f in ranked if f.get("severity") in ("critical", "high", "medium")][:3]

        lines = [
            f"AyaRecon reviewed {total} finding(s): "
            f"{crit} critical, {high} high, {med} medium, "
            f"{severity_counts.get('low', 0)} low, {severity_counts.get('info', 0)} info.",
            "",
            posture,
        ]
        if top:
            lines.append("")
            lines.append("Fix these first:")
            for i, f in enumerate(top, 1):
                fix = f.get("remediation") or "see the technical report"
                lines.append(f"  {i}. {f.get('title')} ({f.get('severity','').upper()}) "
                             f"— {fix}")
        lines.append("")
        lines.append("In plain terms: each finding below says what it is, how an "
                     "attacker could abuse it, and exactly how to fix it. Work top-down "
                     "by severity.")
        return "\n".join(lines)

    # --------------------------------------------------------------- LLM (optional)
    def llm_available(self) -> bool:
        provider = self.config.get("ai_provider", "ollama")
        if provider == "none" or requests is None:
            return False
        if provider == "ollama":
            try:
                r = requests.get(self.config.get("ollama_host") + "/api/tags", timeout=3)
                return r.status_code == 200
            except Exception:
                return False
        if provider in ("openai", "anthropic"):
            return bool(self.config.get("cloud_api_key"))
        return False

    def ollama_models(self) -> list[str]:
        """List locally-pulled Ollama models (empty if Ollama isn't running)."""
        if requests is None:
            return []
        try:
            r = requests.get(self.config.get("ollama_host") + "/api/tags", timeout=3)
            if r.status_code == 200:
                return [m.get("name", "") for m in r.json().get("models", [])]
        except Exception:
            pass
        return []

    def ai_diagnosis(self) -> str:
        """Plain-English status: is the LLM usable, and if not, exactly why + the fix."""
        import shutil
        provider = self.config.get("ai_provider", "ollama")
        if provider == "none":
            return ("AI provider is set to 'none'. The offline analyst still scores and "
                    "correlates findings. For chat, pick 'ollama' in Settings.")
        if requests is None:
            return ("The 'requests' library isn't installed, so the LLM can't be reached. "
                    "Click 'Install Python libraries (pip)' on the Tools tab, then restart. "
                    "The offline analyst works in the meantime.")
        if provider == "ollama":
            if shutil.which("ollama") is None and not self._ollama_reachable():
                return ("Ollama isn't installed. Install it from the Tools tab (or "
                        "ollama.com), then pull a model (e.g. llama3). Until then the "
                        "offline analyst answers your questions.")
            if not self._ollama_reachable():
                return ("Ollama is installed but not responding on "
                        f"{self.config.get('ollama_host')}. Start it (run 'ollama serve' "
                        "or open the Ollama app), then click 'Test AI connection'.")
            models = self.ollama_models()
            if not models:
                return ("Ollama is running but you have no models yet. Pull one below "
                        "(llama3 is a good default): it downloads a few GB once.")
            return (f"✓ Ollama connected with model(s): {', '.join(models)}. "
                    "The AI chat is live.")
        if provider in ("openai", "anthropic"):
            if not self.config.get("cloud_api_key"):
                return (f"Provider '{provider}' needs an API key — add one in Settings. "
                        "The offline analyst works without it.")
            return f"✓ Cloud provider '{provider}' configured. AI chat is live."
        return "Unknown AI provider."

    def _ollama_reachable(self) -> bool:
        if requests is None:
            return False
        try:
            r = requests.get(self.config.get("ollama_host") + "/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def pull_model(self, model: str, on_line=None) -> int:
        """Pull an Ollama model via the CLI, streaming progress. Returns exit code."""
        import shutil
        import subprocess

        def emit(m):
            if on_line:
                on_line(m)

        if shutil.which("ollama") is None:
            emit("Ollama isn't installed yet — install it from the Tools tab first.")
            return -1
        emit(f"$ ollama pull {model}")
        try:
            proc = subprocess.Popen(["ollama", "pull", model],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            for line in iter(proc.stdout.readline, ""):
                emit(line.rstrip("\n"))
            proc.wait()
            emit("Model ready ✓" if proc.returncode == 0 else f"exit {proc.returncode}")
            return proc.returncode
        except Exception as exc:
            emit(f"pull failed: {exc}")
            return -1

    def explain_finding(self, finding: dict) -> str:
        """
        Pen-tester briefing for ONE finding: attack path, impact, remediation,
        references. Uses the curated threat KB, and lets the LLM elaborate when
        one is connected. Risk analysis + defence only — never exploit code.
        """
        brief = exploitation.brief_for_finding(finding)
        header = (f"{finding.get('title','Finding')} "
                  f"[{finding.get('severity','info').upper()}]\n"
                  f"{finding.get('detail','')}\n")
        if brief:
            base = header + "\n" + brief.as_text()
        else:
            fix = finding.get("remediation") or "Review against vendor guidance."
            base = (header + f"\n🛡 Remediation: {fix}\n"
                    "(No specific attack-path briefing on file for this item.)")

        if self.llm_available():
            extra = self._ask_llm(
                "As a penetration-test advisor for an AUTHORISED assessment, expand the "
                "risk briefing for the finding below: explain the realistic attack path "
                "and impact at a conceptual level, and give concrete remediation. Do NOT "
                "provide exploit code, payloads or step-by-step weaponisation — risk "
                "analysis and defence only.",
                [finding])
            if extra:
                base += "\n\n— AI elaboration —\n" + extra
        return base

    def ask(self, question: str, findings: list[dict]) -> str:
        """
        Answer a free-form question about the current findings. Uses the LLM if
        available, otherwise a deterministic responder over the data + threat KB.
        """
        if self.llm_available():
            answer = self._ask_llm(question, findings)
            if answer:
                return answer
        return self._ask_rule_based(question, findings)

    def _ask_rule_based(self, question: str, findings: list[dict]) -> str:
        q = question.lower()
        # Exploitation / "how can this be hacked" questions → threat briefings.
        if any(w in q for w in ("hack", "exploit", "attack", "abuse", "break in",
                                "compromise", "vulnerab", "risk")):
            briefed = []
            for f in findings:
                b = exploitation.brief_for_finding(f)
                if b and f.get("severity") in ("critical", "high", "medium"):
                    briefed.append(f"\n▶ {f.get('title')} ({f.get('severity','').upper()})\n"
                                   + b.as_text())
            if briefed:
                return ("Attack paths for the notable findings (authorised-testing "
                        "risk analysis — no exploit code):\n" + "\n".join(briefed[:12]))
            return ("No findings with a known attack-path briefing yet. Run phases 1–4 "
                    "first, then ask again.")
        if "critical" in q or "most important" in q or "worst" in q:
            crits = [f for f in findings if f.get("severity") == "critical"]
            if not crits:
                return "No critical findings in the current workspace."
            lines = [f"• {f['title']}: {f['detail']}" for f in crits[:20]]
            return "Critical findings:\n" + "\n".join(lines)
        if "secure" in q or "fix" in q or "remediat" in q or "how do i" in q:
            fixes = [f"• {f['title']}: {f['remediation']}" for f in findings
                     if f.get("remediation")]
            if not fixes:
                return "No specific remediation items are recorded yet. Run a scan first."
            return "Top remediation steps:\n" + "\n".join(dict.fromkeys(fixes[:20]))
        if "port" in q:
            ports = [f["detail"] for f in findings if f["category"] == "port"]
            return "Open ports:\n" + "\n".join(f"• {p}" for p in ports) if ports \
                else "No open ports recorded."
        if "subdomain" in q:
            subs = [f["detail"] for f in findings if f["category"] == "subdomain"
                    or (f["category"] == "enum" and "ubdomain" in f["title"])]
            return "Subdomains:\n" + "\n".join(f"• {s}" for s in subs) if subs \
                else "No subdomains recorded."
        # Generic fallback: counts.
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
        summary = ", ".join(f"{v} {k}" for k, v in by_sev.items())
        return (f"I have {len(findings)} findings ({summary}). Ask me about critical "
                "findings, open ports, subdomains, or how to fix something.")

    def _ask_llm(self, question: str, findings: list[dict]) -> str:
        provider = self.config.get("ai_provider", "ollama")
        context = json.dumps([
            {k: f.get(k) for k in ("category", "title", "detail", "severity")}
            for f in findings[:200]
        ], indent=0)
        prompt = (
            "You are AyaRecon, a penetration-testing advisor (made by Ruel) for an "
            "AUTHORISED engagement. Using ONLY the findings below, help the tester "
            "understand risk: for each relevant item explain the realistic attack path "
            "and impact (name the technique/CVE where you can) and give concrete "
            "remediation. Be specific and concise. Do NOT output exploit code, "
            "payloads, or step-by-step weaponisation — this is risk analysis and "
            "defence, not an attack script.\n\n"
            f"FINDINGS:\n{context}\n\nQUESTION: {question}\n\nANSWER:"
        )
        try:
            if provider == "ollama":
                r = requests.post(
                    self.config.get("ollama_host") + "/api/generate",
                    json={"model": self.config.get("ollama_model", "llama3"),
                          "prompt": prompt, "stream": False},
                    timeout=120,
                )
                r.raise_for_status()
                return r.json().get("response", "").strip()
            if provider == "openai":
                r = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.config.get('cloud_api_key')}"},
                    json={"model": self.config.get("cloud_model") or "gpt-4o-mini",
                          "messages": [{"role": "user", "content": prompt}]},
                    timeout=120,
                )
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"].strip()
            if provider == "anthropic":
                r = requests.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": self.config.get("cloud_api_key"),
                             "anthropic-version": "2023-06-01"},
                    json={"model": self.config.get("cloud_model") or "claude-3-5-haiku-latest",
                          "max_tokens": 1024,
                          "messages": [{"role": "user", "content": prompt}]},
                    timeout=120,
                )
                r.raise_for_status()
                return r.json()["content"][0]["text"].strip()
        except Exception:
            return ""
        return ""

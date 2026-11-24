"""
AyaRecon — PART 5/6: report generation & export.
Made by Ruel.

Generates the three auto-documents (executive summary, full technical report,
remediation roadmap) and exports findings to HTML / CSV / JSON / PDF.

All generators degrade gracefully: PDF needs reportlab, styled HTML uses a
built-in template (no jinja2 required, though it's used if present).
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas as _pdf_canvas
except ImportError:  # pragma: no cover
    _pdf_canvas = None

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {
    "critical": "#b00020", "high": "#d9534f", "medium": "#e0a800",
    "low": "#5bc0de", "info": "#6c757d",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEV_ORDER.index(f.get("severity", "info"))
                  if f.get("severity") in SEV_ORDER else 99)


# --------------------------------------------------------------- the three documents
def executive_summary_doc(findings, counts, ai_summary, workspace="default") -> str:
    lines = [
        "AYA — EXECUTIVE SUMMARY",
        "Made by Ruel",
        f"Workspace: {workspace}    Generated: {_now()}",
        "=" * 60,
        "",
        ai_summary,
        "",
        "Findings by severity:",
    ]
    for sev in SEV_ORDER:
        lines.append(f"  {sev.capitalize():<9}: {counts.get(sev, 0)}")
    return "\n".join(lines)


def technical_report_doc(findings, workspace="default") -> str:
    lines = [
        "AYA — FULL TECHNICAL REPORT",
        "Made by Ruel",
        f"Workspace: {workspace}    Generated: {_now()}",
        "=" * 60,
    ]
    for f in _sort_findings(findings):
        lines += [
            "",
            f"[{f.get('severity', 'info').upper()}] {f.get('title')}",
            f"  Target   : {f.get('target', '')}",
            f"  Category : {f.get('category')}",
            f"  Detail   : {f.get('detail')}",
        ]
        if f.get("ai_reasoning"):
            lines.append(f"  Analysis : {f['ai_reasoning']}")
        if f.get("remediation"):
            lines.append(f"  Fix      : {f['remediation']}")
    return "\n".join(lines)


def remediation_roadmap_doc(findings, workspace="default") -> str:
    lines = [
        "AYA — REMEDIATION ROADMAP (fix highest risk first)",
        "Made by Ruel",
        f"Workspace: {workspace}    Generated: {_now()}",
        "=" * 60,
    ]
    n = 1
    for f in _sort_findings(findings):
        if f.get("severity") in ("info",) or not f.get("remediation"):
            continue
        lines += [
            "",
            f"{n}. [{f.get('severity', '').upper()}] {f.get('title')}",
            f"   Why : {f.get('ai_reasoning') or f.get('detail')}",
            f"   Do  : {f.get('remediation')}",
        ]
        n += 1
    if n == 1:
        lines.append("\nNothing actionable — no medium+ findings with fixes.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- exports
def export_json(findings, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    return path


def export_csv(findings, path: str | Path) -> Path:
    path = Path(path)
    cols = ["severity", "category", "title", "target", "detail", "ai_reasoning", "remediation"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for f in _sort_findings(findings):
            writer.writerow({c: f.get(c, "") for c in cols})
    return path


def export_html(findings, path: str | Path, counts=None, ai_summary="",
                workspace="default") -> Path:
    path = Path(path)
    counts = counts or {}
    try:
        from .modules import exploitation
    except Exception:
        exploitation = None

    rows = []
    for f in _sort_findings(findings):
        color = SEV_COLOR.get(f.get("severity", "info"), "#6c757d")
        attack = impact = ""
        if exploitation:
            b = exploitation.brief_for_finding(f)
            if b:
                attack, impact = b.attack, b.impact
        analysis = _esc(f.get("ai_reasoning"))
        if attack:
            analysis += (f'<div class="attack"><b>How it\'s attacked:</b> {_esc(attack)}'
                         f'<br><b>Impact:</b> {_esc(impact)}</div>')
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.get('severity','info').upper()}</span></td>
          <td>{_esc(f.get('category'))}</td>
          <td><strong>{_esc(f.get('title'))}</strong><br><span class="detail">{_esc(f.get('detail'))}</span></td>
          <td>{analysis}</td>
          <td>{_esc(f.get('remediation'))}</td>
        </tr>""")

    chips = " ".join(
        f'<span class="chip" style="border-color:{SEV_COLOR[s]};color:{SEV_COLOR[s]}">'
        f'{s}: {counts.get(s, 0)}</span>'
        for s in SEV_ORDER
    )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AyaRecon Report — {_esc(workspace)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin:0;
          background:#0f1117; color:#e6e6e6; }}
  header {{ background:#161a23; padding:24px 32px; border-bottom:2px solid #2a3142; }}
  h1 {{ margin:0; font-size:22px; }}
  .by {{ color:#8aa0c7; font-size:13px; margin-top:4px; }}
  .wrap {{ padding:24px 32px; }}
  .summary {{ background:#161a23; border:1px solid #2a3142; border-radius:10px;
              padding:16px 20px; margin-bottom:20px; }}
  .chip {{ display:inline-block; border:1px solid; border-radius:20px;
           padding:2px 12px; margin-right:8px; font-size:13px; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #222838;
            vertical-align:top; }}
  th {{ color:#8aa0c7; font-weight:600; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:6px; font-size:11px;
            font-weight:700; }}
  .detail {{ color:#9aa4b2; font-size:12px; }}
  .attack {{ margin-top:6px; padding:6px 8px; background:#1a1320; border-left:3px solid #f85149;
             border-radius:4px; font-size:12px; color:#e8c0c0; }}
  .summary {{ white-space:pre-wrap; line-height:1.5; }}
  footer {{ padding:18px 32px; color:#6c7684; font-size:12px; }}
</style></head>
<body>
<header>
  <h1>🛡️ AyaRecon — Security Report</h1>
  <div class="by">Workspace: {_esc(workspace)} · Generated {_now()} · Made by Ruel</div>
</header>
<div class="wrap">
  <div class="summary">
    <div style="margin-bottom:10px">{chips}</div>
    <div>{_esc(ai_summary)}</div>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Finding</th>
    <th>AyaRecon analysis</th><th>Remediation</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>
<footer>Generated by AyaRecon — recon, defend, understand. Made by Ruel.
Use only on systems you own or are authorised to test.</footer>
</body></html>"""
    path.write_text(html, encoding="utf-8")
    return path


def export_pdf(findings, path: str | Path, counts=None, ai_summary="",
               workspace="default") -> Path | None:
    path = Path(path)
    if _pdf_canvas is None:
        # Fallback: write the text technical report next to the requested path.
        alt = path.with_suffix(".txt")
        alt.write_text(technical_report_doc(findings, workspace), encoding="utf-8")
        return alt

    c = _pdf_canvas.Canvas(str(path), pagesize=A4)
    width, height = A4
    y = height - 25 * mm

    def line(text, size=10, dy=6, bold=False):
        nonlocal y
        if y < 20 * mm:
            c.showPage()
            y = height - 25 * mm
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(20 * mm, y, text[:110])
        y -= (dy + size) * 0.5 + 4

    line("AyaRecon — Security Report", 18, bold=True)
    line(f"Workspace: {workspace}   Generated: {_now()}   Made by Ruel", 9)
    line("", 4)
    counts = counts or {}
    line("Severity summary: " + ", ".join(
        f"{s}={counts.get(s,0)}" for s in SEV_ORDER), 10, bold=True)
    line("", 4)
    if ai_summary:
        for chunk in _wrap(ai_summary, 100):
            line(chunk, 9)
    line("", 6)
    line("Findings", 13, bold=True)
    for f in _sort_findings(findings):
        line(f"[{f.get('severity','info').upper()}] {f.get('title')}", 10, bold=True)
        for chunk in _wrap(f"{f.get('detail','')}", 100):
            line("   " + chunk, 9)
        if f.get("remediation"):
            for chunk in _wrap("Fix: " + f["remediation"], 100):
                line("   " + chunk, 9)
    c.save()
    return path


# --------------------------------------------------------------------------- helpers
def _esc(s: Any) -> str:
    s = "" if s is None else str(s)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _wrap(text: str, width: int) -> list[str]:
    words = str(text).split()
    out, cur = [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            out.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        out.append(cur)
    return out or [""]

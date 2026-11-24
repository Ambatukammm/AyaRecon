"""
AyaRecon — live CVE feed via the NVD API.
Made by Ruel.

The offline CVE knowledge base (modules/vuln_assessment.py) is the always-works
baseline. This module adds LIVE lookups against NIST's National Vulnerability
Database so AyaRecon can flag the newest CVEs for the exact products/versions it
discovers — and pull a feed of the most recently published CVEs.

Results are cached on disk (24h TTL) to stay fast and within NVD's rate limits.
An optional API key (Settings) raises those limits. Everything degrades to the
offline DB when there's no network or the API is unavailable.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    from ..config import APP_DIR
    CACHE_DIR = APP_DIR / "cache"
except Exception:  # pragma: no cover
    import os
    CACHE_DIR = Path(os.path.expanduser("~")) / ".ayarecon" / "cache"

CACHE_DIR.mkdir(parents=True, exist_ok=True)
_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TTL = 24 * 3600
_last_call = [0.0]   # simple throttle timestamp


def available() -> bool:
    return requests is not None


def _cache_path(key: str) -> Path:
    h = hashlib.sha1(key.encode()).hexdigest()[:16]
    return CACHE_DIR / f"nvd_{h}.json"


def _cached(key: str):
    p = _cache_path(key)
    if p.exists() and (time.time() - p.stat().st_mtime) < _TTL:
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _store(key: str, data) -> None:
    try:
        _cache_path(key).write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


def _throttle(api_key: str) -> None:
    # NVD allows ~5 req/30s without a key, ~50/30s with one. Keep a safe gap.
    gap = 1.5 if api_key else 6.5
    delta = time.time() - _last_call[0]
    if delta < gap:
        time.sleep(gap - delta)
    _last_call[0] = time.time()


def _parse(vulns: list) -> list[dict]:
    out = []
    for item in vulns:
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        score, sev = None, ""
        metrics = cve.get("metrics", {})
        for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if mkey in metrics and metrics[mkey]:
                data = metrics[mkey][0].get("cvssData", {})
                score = data.get("baseScore")
                sev = (metrics[mkey][0].get("baseSeverity")
                       or data.get("baseSeverity") or "").lower()
                break
        out.append({"id": cid, "score": score, "severity": sev or "medium",
                    "summary": desc, "published": cve.get("published", "")})
    return out


def _severity_band(score, sev) -> str:
    if sev in ("critical", "high", "medium", "low"):
        return sev
    if isinstance(score, (int, float)):
        if score >= 9: return "critical"
        if score >= 7: return "high"
        if score >= 4: return "medium"
        return "low"
    return "medium"


def search(keyword: str, limit: int = 8, api_key: str = "") -> list[dict]:
    """Search NVD for CVEs matching a product keyword (e.g. 'OpenSSH 7.2')."""
    keyword = (keyword or "").strip()
    if not keyword or not available():
        return []
    ckey = f"search::{keyword}::{limit}"
    hit = _cached(ckey)
    if hit is not None:
        return hit
    params = {"keywordSearch": keyword, "resultsPerPage": limit}
    headers = {"User-Agent": "AyaRecon/3.0 (by Ruel)"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        _throttle(api_key)
        r = requests.get(_BASE, params=params, headers=headers, timeout=30)
        if r.status_code != 200:
            return []
        rows = _parse(r.json().get("vulnerabilities", []))
        for row in rows:
            row["severity"] = _severity_band(row["score"], row["severity"])
        _store(ckey, rows)
        return rows
    except Exception:
        return []


def latest(days: int = 7, limit: int = 30, api_key: str = "") -> list[dict]:
    """Pull the most recently published CVEs (a 'newest vulnerabilities' feed)."""
    if not available():
        return []
    ckey = f"latest::{days}::{limit}"
    hit = _cached(ckey)
    if hit is not None:
        return hit
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": limit,
    }
    headers = {"User-Agent": "AyaRecon/3.0 (by Ruel)"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        _throttle(api_key)
        r = requests.get(_BASE, params=params, headers=headers, timeout=45)
        if r.status_code != 200:
            return []
        rows = _parse(r.json().get("vulnerabilities", []))
        for row in rows:
            row["severity"] = _severity_band(row["score"], row["severity"])
        rows.sort(key=lambda x: x.get("published", ""), reverse=True)
        _store(ckey, rows)
        return rows
    except Exception:
        return []


def enrich_findings(findings: list[dict], api_key: str = "",
                    progress=None) -> list[dict]:
    """
    For findings that carry a product/version string, query NVD and return NEW
    'vuln' findings for live CVE matches. Caches per product so repeated runs are
    fast. Pure read-only enrichment.
    """
    seen_products = set()
    results: list[dict] = []
    targets = []
    for f in findings:
        data = f.get("data", {}) or {}
        product = (data.get("product") or data.get("banner") or "").strip()
        if product and len(product) > 3 and product.lower() not in seen_products:
            seen_products.add(product.lower())
            targets.append((product, f.get("target", "")))

    for i, (product, target) in enumerate(targets):
        if progress:
            progress(i + 1, len(targets))
        for cve in search(product, limit=5, api_key=api_key):
            if not cve["id"]:
                continue
            results.append({
                "category": "vuln",
                "title": f"[NVD] {cve['id']} affects {product}",
                "detail": (cve["summary"][:300] + "…") if len(cve["summary"]) > 300
                          else cve["summary"],
                "data": {"cve": cve["id"], "score": cve["score"],
                         "product": product, "published": cve["published"],
                         "source": "NVD-live"},
                "severity": cve["severity"],
                "ai_reasoning": f"Live NVD match for '{product}'. CVSS "
                                f"{cve['score']}. Published {cve['published'][:10]}.",
                "remediation": "Check the vendor advisory for this CVE and patch/upgrade "
                               "the affected component.",
                "target": target,
            })
    return results

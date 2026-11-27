"""
AyaRecon — local SQLite storage.
Made by Ruel.

Everything AyaRecon discovers is written to a local SQLite database. Each
*workspace* is an isolated project; findings, scans and the permission audit
log are scoped to a workspace so unrelated engagements never mix.

No data ever leaves the device through this layer.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .config import DEFAULT_DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    created_at  TEXT NOT NULL,
    notes       TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id  INTEGER NOT NULL,
    target        TEXT NOT NULL,
    module        TEXT NOT NULL,      -- e.g. 'passive.dns', 'active.portscan'
    mode          TEXT NOT NULL,      -- 'passive' | 'active' | 'enumeration' | 'defensive'
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT DEFAULT 'running',
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id  INTEGER NOT NULL,
    scan_id       INTEGER,
    target        TEXT NOT NULL,
    category      TEXT NOT NULL,      -- 'dns', 'port', 'ssl', 'breach', ...
    title         TEXT NOT NULL,
    detail        TEXT DEFAULT '',    -- human-readable
    data_json     TEXT DEFAULT '{}',  -- structured payload
    severity      TEXT DEFAULT 'info',-- critical|high|medium|low|info
    ai_reasoning  TEXT DEFAULT '',
    remediation   TEXT DEFAULT '',
    created_at    TEXT NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE TABLE IF NOT EXISTS permission_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id  INTEGER,
    target        TEXT NOT NULL,
    module        TEXT NOT NULL,
    mode          TEXT NOT NULL,
    confirmed     INTEGER NOT NULL,   -- 1 = user confirmed permission
    confirmation_text TEXT DEFAULT '',
    user          TEXT DEFAULT '',
    timestamp     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_ws ON findings(workspace_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_ws ON scans(workspace_id);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Thread-safe-ish SQLite wrapper (one connection guarded by a lock)."""

    def __init__(self, path: Path | str = DEFAULT_DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, timeout=30
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ----------------------------------------------------------------- workspaces
    def create_workspace(self, name: str, notes: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO workspaces(name, created_at, notes) VALUES (?,?,?)",
                (name, _utcnow(), notes),
            )
            self._conn.commit()
            if cur.lastrowid:
                return cur.lastrowid
            row = self._conn.execute(
                "SELECT id FROM workspaces WHERE name=?", (name,)
            ).fetchone()
            return row["id"]

    def list_workspaces(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM workspaces ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_workspace(self, workspace_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM findings WHERE workspace_id=?", (workspace_id,))
            self._conn.execute("DELETE FROM scans WHERE workspace_id=?", (workspace_id,))
            self._conn.execute("DELETE FROM permission_log WHERE workspace_id=?", (workspace_id,))
            self._conn.execute("DELETE FROM workspaces WHERE id=?", (workspace_id,))
            self._conn.commit()

    # ----------------------------------------------------------------- scans
    def start_scan(self, workspace_id: int, target: str, module: str, mode: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans(workspace_id, target, module, mode, started_at, status)"
                " VALUES (?,?,?,?,?,'running')",
                (workspace_id, target, module, mode, _utcnow()),
            )
            self._conn.commit()
            return cur.lastrowid

    def finish_scan(self, scan_id: int, status: str = "done") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_at=?, status=? WHERE id=?",
                (_utcnow(), status, scan_id),
            )
            self._conn.commit()

    def list_scans(self, workspace_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans WHERE workspace_id=? ORDER BY started_at DESC",
                (workspace_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ----------------------------------------------------------------- findings
    def add_finding(
        self,
        workspace_id: int,
        target: str,
        category: str,
        title: str,
        detail: str = "",
        data: dict[str, Any] | None = None,
        severity: str = "info",
        scan_id: int | None = None,
        ai_reasoning: str = "",
        remediation: str = "",
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO findings
                   (workspace_id, scan_id, target, category, title, detail,
                    data_json, severity, ai_reasoning, remediation, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    workspace_id, scan_id, target, category, title, detail,
                    json.dumps(data or {}), severity, ai_reasoning, remediation,
                    _utcnow(),
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def update_finding_ai(
        self, finding_id: int, severity: str, ai_reasoning: str, remediation: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET severity=?, ai_reasoning=?, remediation=? WHERE id=?",
                (severity, ai_reasoning, remediation, finding_id),
            )
            self._conn.commit()

    def list_findings(
        self, workspace_id: int, severity: str | None = None
    ) -> list[dict[str, Any]]:
        with self._lock:
            if severity:
                rows = self._conn.execute(
                    "SELECT * FROM findings WHERE workspace_id=? AND severity=?"
                    " ORDER BY created_at DESC",
                    (workspace_id, severity),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM findings WHERE workspace_id=? ORDER BY created_at DESC",
                    (workspace_id,),
                ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["data"] = json.loads(d.get("data_json") or "{}")
                except json.JSONDecodeError:
                    d["data"] = {}
                out.append(d)
            return out

    def severity_counts(self, workspace_id: int) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings WHERE workspace_id=?"
                " GROUP BY severity",
                (workspace_id,),
            ).fetchall()
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for r in rows:
                counts[r["severity"]] = r["n"]
            return counts

    def clear_findings(self, workspace_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM findings WHERE workspace_id=?", (workspace_id,))
            self._conn.commit()

    # ----------------------------------------------------------------- permission log
    def log_permission(
        self,
        workspace_id: int | None,
        target: str,
        module: str,
        mode: str,
        confirmed: bool,
        confirmation_text: str = "",
        user: str = "",
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO permission_log
                   (workspace_id, target, module, mode, confirmed,
                    confirmation_text, user, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    workspace_id, target, module, mode, 1 if confirmed else 0,
                    confirmation_text, user, _utcnow(),
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_permission_log(self, workspace_id: int | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if workspace_id is None:
                rows = self._conn.execute(
                    "SELECT * FROM permission_log ORDER BY timestamp DESC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM permission_log WHERE workspace_id=? ORDER BY timestamp DESC",
                    (workspace_id,),
                ).fetchall()
            return [dict(r) for r in rows]

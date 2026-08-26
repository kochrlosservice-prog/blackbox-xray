"""BLACKBOX X-RAY — SQLite evidence store (no Firestore dependency)."""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import EVIDENCE_DB


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db() -> sqlite3.Connection:
    path = Path(EVIDENCE_DB)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign ON evidence(campaign_id)")
    conn.commit()
    return conn


def record(campaign_id: str, event_type: str, payload: dict[str, Any]) -> str:
    entry_id = str(uuid.uuid4())
    with _db() as conn:
        conn.execute(
            "INSERT INTO evidence VALUES (?,?,?,?,?)",
            (entry_id, campaign_id, event_type, json.dumps(payload, default=str), _now()),
        )
    return entry_id


def get_campaign(campaign_id: str) -> list[dict[str, Any]]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE campaign_id=? ORDER BY recorded_at",
            (campaign_id,),
        ).fetchall()
    return [dict(r) | {"payload": json.loads(r["payload"])} for r in rows]


def get_all(limit: int = 100) -> list[dict[str, Any]]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM evidence ORDER BY recorded_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) | {"payload": json.loads(r["payload"])} for r in rows]

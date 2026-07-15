"""Lightweight SQLite store for investigation history (`osintx report
latest`, future `osintx history` command, etc). Uses stdlib sqlite3
directly rather than an ORM to keep the dependency footprint small."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from core.schema import Investigation

DB_PATH = Path.home() / ".osintx" / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    entity_count INTEGER DEFAULT 0,
    data_json TEXT NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(_SCHEMA)
    return conn


def save_investigation(investigation: Investigation) -> None:
    conn = _connect()
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO investigations "
            "(id, target_type, target_value, started_at, completed_at, entity_count, data_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                investigation.id,
                investigation.target_type,
                investigation.target_value,
                investigation.started_at,
                investigation.completed_at,
                len(investigation.entities),
                json.dumps(investigation.to_dict()),
            ),
        )
    conn.close()


def get_latest() -> dict | None:
    conn = _connect()
    row = conn.execute(
        "SELECT data_json FROM investigations ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return json.loads(row[0]) if row else None


def get_by_id(investigation_id: str) -> dict | None:
    conn = _connect()
    row = conn.execute(
        "SELECT data_json FROM investigations WHERE id = ?", (investigation_id,)
    ).fetchone()
    conn.close()
    return json.loads(row[0]) if row else None


def list_history(limit: int = 20) -> list[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT id, target_type, target_value, started_at, entity_count "
        "FROM investigations ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [
        {"id": r[0], "target_type": r[1], "target_value": r[2], "started_at": r[3], "entity_count": r[4]}
        for r in rows
    ]

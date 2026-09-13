"""SQLite history with bounded waits and deterministic connection cleanup."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from core.schema import Investigation

DB_PATH = Path.home() / '.osintx' / 'history.db'
_SCHEMA = '''CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_value TEXT NOT NULL,
    started_at TEXT NOT NULL, completed_at TEXT, entity_count INTEGER DEFAULT 0, data_json TEXT NOT NULL
);'''


class HistoryError(ValueError):
    pass


def _decode(row):
    if row is None:
        return None
    try:
        data = json.loads(row[0])
        if not isinstance(data, dict) or not isinstance(data.get('entities', []), list):
            raise ValueError
        return data
    except (ValueError, TypeError) as exc:
        raise HistoryError('Stored investigation is malformed; check the history database') from exc


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        conn.execute(_SCHEMA)
    except sqlite3.Error:
        conn.close()
        raise
    return conn


def save_investigation(inv: Investigation) -> None:
    with closing(_connect()) as conn, conn:
        conn.execute('INSERT OR REPLACE INTO investigations (id,target_type,target_value,started_at,completed_at,entity_count,data_json) VALUES (?,?,?,?,?,?,?)',
                     (inv.id, inv.target_type, inv.target_value, inv.started_at, inv.completed_at, len(inv.entities), json.dumps(inv.to_dict())))


def get_latest() -> dict | None:
    with closing(_connect()) as conn:
        row = conn.execute('SELECT data_json FROM investigations ORDER BY started_at DESC LIMIT 1').fetchone()
    return _decode(row)


def get_by_id(investigation_id: str) -> dict | None:
    with closing(_connect()) as conn:
        row = conn.execute('SELECT data_json FROM investigations WHERE id = ?', (investigation_id,)).fetchone()
    return _decode(row)


def list_history(limit: int = 20) -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute('SELECT id,target_type,target_value,started_at,entity_count FROM investigations ORDER BY started_at DESC LIMIT ?', (limit,)).fetchall()
    return [dict(zip(('id', 'target_type', 'target_value', 'started_at', 'entity_count'), row)) for row in rows]

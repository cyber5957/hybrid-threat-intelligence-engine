"""Small SQLite persistence layer for the local Sentinel service."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", Path(__file__).resolve().parent.parent / "data" / "sentinel.db"))


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
          id TEXT PRIMARY KEY, raw_text TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS indicators (
          id INTEGER PRIMARY KEY, value TEXT NOT NULL, type TEXT NOT NULL,
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT 'unknown',
          risk_score INTEGER, alert_id TEXT REFERENCES alerts(id), UNIQUE(value, type)
        );
        CREATE TABLE IF NOT EXISTS enrichment_results (
          id INTEGER PRIMARY KEY, indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
          provider TEXT NOT NULL, verdict TEXT NOT NULL, risk_score INTEGER, metadata TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'complete', checked_at TEXT NOT NULL, cache_key TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_enrichment_cache ON enrichment_results(cache_key, checked_at DESC);
        CREATE TABLE IF NOT EXISTS activity_log (
          id INTEGER PRIMARY KEY, action TEXT NOT NULL, message TEXT NOT NULL,
          details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at DESC);
        CREATE TABLE IF NOT EXISTS enrichment_jobs (
          id TEXT PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES alerts(id), status TEXT NOT NULL,
          total INTEGER NOT NULL, completed INTEGER NOT NULL DEFAULT 0, warnings TEXT NOT NULL DEFAULT '[]',
          created_at TEXT NOT NULL, finished_at TEXT
        );
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(enrichment_results)")}
        if "status" not in columns:
            db.execute("ALTER TABLE enrichment_results ADD COLUMN status TEXT NOT NULL DEFAULT 'complete'")


def record_activity(action: str, message: str, details: dict[str, Any] | None = None) -> None:
    from datetime import datetime, timezone
    with connect() as db:
        db.execute("INSERT INTO activity_log(action,message,details,created_at) VALUES(?,?,?,?)",
                   (action, message, json.dumps(details or {}), datetime.now(timezone.utc).isoformat()))

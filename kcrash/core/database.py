from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

from kcrash.exceptions import DatabaseError


@dataclass
class CrashRecord:
    id: str
    fingerprint_hash: str
    hostname: str
    vmcore_path: str
    root_cause: str
    confidence: float
    severity_level: str
    severity_score: float
    verdict_agent: str
    patch_type: str
    patch_valid: bool
    status: str
    duration_ms: float
    token_total: int
    created_at: str
    report_json: str = ""


@dataclass
class CrashTrend:
    fingerprint_hash: str
    top_function: str
    error_class: str
    occurrence_count: int
    first_seen: str
    last_seen: str
    affected_hosts: int
    avg_confidence: float


SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS crash_history (
    id TEXT PRIMARY KEY,
    fingerprint_hash TEXT NOT NULL,
    hostname TEXT NOT NULL,
    vmcore_path TEXT NOT NULL,
    root_cause TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.0,
    severity_level TEXT NOT NULL DEFAULT 'UNKNOWN',
    severity_score REAL NOT NULL DEFAULT 0.0,
    verdict_agent TEXT NOT NULL DEFAULT '',
    patch_type TEXT NOT NULL DEFAULT '',
    patch_valid INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    duration_ms REAL NOT NULL DEFAULT 0.0,
    token_total INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    report_json TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_crash_fingerprint ON crash_history(fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_crash_hostname ON crash_history(hostname);
CREATE INDEX IF NOT EXISTS idx_crash_created ON crash_history(created_at);
CREATE INDEX IF NOT EXISTS idx_crash_severity ON crash_history(severity_level);
CREATE INDEX IF NOT EXISTS idx_crash_status ON crash_history(status);

CREATE TABLE IF NOT EXISTS crash_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crash_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (crash_id) REFERENCES crash_history(id)
);

CREATE INDEX IF NOT EXISTS idx_events_crash ON crash_events(crash_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON crash_events(event_type);

CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crash_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    destination TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Database:
    def __init__(self, db_path: str = "kcrash.db") -> None:
        self._db_path = Path(db_path)
        self._local = threading.local()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self._db_path),
                timeout=30,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_schema(self) -> None:
        conn = self._get_conn()
        try:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
            conn.commit()
        except Exception as exc:
            raise DatabaseError(f"Schema initialization failed: {exc}") from exc

    def save_crash(self, record: dict[str, Any]) -> None:
        with self.transaction() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO crash_history
                   (id, fingerprint_hash, hostname, vmcore_path, root_cause,
                    confidence, severity_level, severity_score, verdict_agent,
                    patch_type, patch_valid, status, duration_ms, token_total,
                    created_at, report_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["id"],
                    record["fingerprint_hash"],
                    record["hostname"],
                    record["vmcore_path"],
                    record.get("root_cause", ""),
                    record.get("confidence", 0.0),
                    record.get("severity_level", "UNKNOWN"),
                    record.get("severity_score", 0.0),
                    record.get("verdict_agent", ""),
                    record.get("patch_type", ""),
                    1 if record.get("patch_valid") else 0,
                    record.get("status", "completed"),
                    record.get("duration_ms", 0.0),
                    record.get("token_total", 0),
                    record.get("created_at", ""),
                    json.dumps(record.get("report", {}), default=str),
                ),
            )

    def get_crash(self, crash_id: str) -> CrashRecord | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM crash_history WHERE id = ?", (crash_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def get_crashes_by_fingerprint(
        self, fingerprint_hash: str, limit: int = 100
    ) -> list[CrashRecord]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM crash_history WHERE fingerprint_hash = ? ORDER BY created_at DESC LIMIT ?",
            (fingerprint_hash, limit),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def get_crashes_by_hostname(
        self, hostname: str, limit: int = 100
    ) -> list[CrashRecord]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM crash_history WHERE hostname = ? ORDER BY created_at DESC LIMIT ?",
            (hostname, limit),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def get_recent_crashes(self, hours: int = 24, limit: int = 500) -> list[CrashRecord]:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM crash_history
               WHERE created_at >= datetime('now', ?)
               ORDER BY created_at DESC LIMIT ?""",
            (f"-{hours} hours", limit),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def get_crash_count(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) as cnt FROM crash_history").fetchone()
        return row["cnt"]

    def get_trends(self, days: int = 30, min_count: int = 2) -> list[CrashTrend]:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT
                   fingerprint_hash,
                   MIN(root_cause) as top_function,
                   MIN(severity_level) as error_class,
                   COUNT(*) as occurrence_count,
                   MIN(created_at) as first_seen,
                   MAX(created_at) as last_seen,
                   COUNT(DISTINCT hostname) as affected_hosts,
                   AVG(confidence) as avg_confidence
               FROM crash_history
               WHERE created_at >= datetime('now', ?)
               GROUP BY fingerprint_hash
               HAVING occurrence_count >= ?
               ORDER BY occurrence_count DESC""",
            (f"-{days} days", min_count),
        ).fetchall()
        return [
            CrashTrend(
                fingerprint_hash=r["fingerprint_hash"],
                top_function=r["top_function"],
                error_class=r["error_class"],
                occurrence_count=r["occurrence_count"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                affected_hosts=r["affected_hosts"],
                avg_confidence=r["avg_confidence"],
            )
            for r in rows
        ]

    def log_event(self, crash_id: str, event_type: str, event_data: dict) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO crash_events (crash_id, event_type, event_data) VALUES (?, ?, ?)",
                (crash_id, event_type, json.dumps(event_data, default=str)),
            )

    def log_notification(
        self, crash_id: str, channel: str, destination: str, status: str, error: str = ""
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO notification_log (crash_id, channel, destination, status, error) VALUES (?, ?, ?, ?, ?)",
                (crash_id, channel, destination, status, error),
            )

    def purge_old(self, days: int = 90) -> int:
        with self.transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM crash_history WHERE created_at < datetime('now', ?)",
                (f"-{days} days",),
            )
            return cursor.rowcount

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> CrashRecord:
        return CrashRecord(
            id=row["id"],
            fingerprint_hash=row["fingerprint_hash"],
            hostname=row["hostname"],
            vmcore_path=row["vmcore_path"],
            root_cause=row["root_cause"],
            confidence=row["confidence"],
            severity_level=row["severity_level"],
            severity_score=row["severity_score"],
            verdict_agent=row["verdict_agent"],
            patch_type=row["patch_type"],
            patch_valid=bool(row["patch_valid"]),
            status=row["status"],
            duration_ms=row["duration_ms"],
            token_total=row["token_total"],
            created_at=row["created_at"],
            report_json=row["report_json"],
        )

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn:
            conn.close()
            self._local.conn = None

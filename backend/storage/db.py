"""
Persistent Storage — SQLite dual-write layer.

Writes to SQLite AFTER in-memory storage (non-blocking).
Feature-gated by USE_PERSISTENT_STORAGE env var.
Zero changes to existing in-memory flow.
"""
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

# Module-level state
_db: Optional[sqlite3.Connection] = None
_db_lock = threading.Lock()
_db_initialized = False


def _get_db_path() -> str:
    """Get the SQLite database file path."""
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "ia_shield.db")


def init_db() -> bool:
    """
    Initialize SQLite database and create tables if they don't exist.
    Returns True if successful, False if disabled or failed.
    """
    global _db, _db_initialized

    from config import get_settings
    settings = get_settings()

    if not getattr(settings, "USE_PERSISTENT_STORAGE", False):
        return False

    try:
        db_path = _get_db_path()
        _db = sqlite3.connect(db_path, check_same_thread=False)
        # WAL mode for concurrent reads
        _db.execute("PRAGMA journal_mode=WAL")
        _db.execute("PRAGMA synchronous=NORMAL")

        _db.executescript("""
            CREATE TABLE IF NOT EXISTS analysis_records (
                id TEXT PRIMARY KEY,
                email_id TEXT,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT,
                indicators TEXT DEFAULT '[]',
                urls_analyzed TEXT DEFAULT '[]',
                analyzed_at TEXT NOT NULL,
                anomaly_score REAL,
                false_positive_reported INTEGER DEFAULT 0,
                false_positive_reason TEXT
            );

            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                reason TEXT,
                reported_at TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analysis_records(id)
            );

            CREATE TABLE IF NOT EXISTS stats_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_analysis_verdict
                ON analysis_records(verdict);
            CREATE INDEX IF NOT EXISTS idx_analysis_date
                ON analysis_records(analyzed_at);
            CREATE INDEX IF NOT EXISTS idx_fp_analysis
                ON false_positives(analysis_id);
        """)

        _db.commit()
        _db_initialized = True
        print(f"[Storage] SQLite initialized at {db_path}")
        return True

    except Exception as e:
        print(f"[Storage] Failed to initialize SQLite: {e}")
        _db_initialized = False
        return False


def write_analysis(record: dict) -> bool:
    """
    Write an analysis record to SQLite.
    Called AFTER in-memory write — never blocks the main flow.
    Returns True on success, False on failure (non-fatal).
    """
    global _db

    if not _db_initialized or _db is None:
        return False

    try:
        with _db_lock:
            _db.execute(
                """
                INSERT OR REPLACE INTO analysis_records
                (id, email_id, verdict, confidence, reason, indicators,
                 urls_analyzed, analyzed_at, anomaly_score,
                 false_positive_reported, false_positive_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.get("id", ""),
                    record.get("email_id"),
                    record.get("verdict", "review_needed"),
                    record.get("confidence", 0.0),
                    record.get("reason", ""),
                    json.dumps(record.get("indicators", [])),
                    json.dumps(record.get("urls_analyzed", [])),
                    record.get("analyzed_at", datetime.now(timezone.utc).isoformat()),
                    record.get("anomaly_score"),
                    1 if record.get("false_positive_reported") else 0,
                    record.get("false_positive_reason"),
                ),
            )
            _db.commit()
        return True

    except Exception as e:
        print(f"[Storage] Failed to write analysis: {e}")
        return False


def write_false_positive(analysis_id: str, reason: Optional[str] = None) -> bool:
    """
    Record a false positive report in SQLite.
    Also updates the analysis_record's false_positive flags.
    """
    global _db

    if not _db_initialized or _db is None:
        return False

    try:
        with _db_lock:
            # Insert false positive record
            _db.execute(
                """
                INSERT INTO false_positives (analysis_id, reason, reported_at)
                VALUES (?, ?, ?)
                """,
                (analysis_id, reason, datetime.now(timezone.utc).isoformat()),
            )
            # Update the analysis record
            _db.execute(
                """
                UPDATE analysis_records
                SET false_positive_reported = 1, false_positive_reason = ?
                WHERE id = ?
                """,
                (reason, analysis_id),
            )
            _db.commit()
        return True

    except Exception as e:
        print(f"[Storage] Failed to write false positive: {e}")
        return False


def get_analysis_history(limit: int = 50) -> list[dict]:
    """
    Retrieve analysis history from SQLite.
    Returns list of dicts matching the in-memory format.
    """
    global _db

    if not _db_initialized or _db is None:
        return []

    try:
        with _db_lock:
            cursor = _db.execute(
                """
                SELECT id, email_id, verdict, confidence, reason,
                       indicators, urls_analyzed, analyzed_at,
                       anomaly_score, false_positive_reported,
                       false_positive_reason
                FROM analysis_records
                ORDER BY analyzed_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()

        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "email_id": row[1],
                "verdict": row[2],
                "confidence": row[3],
                "reason": row[4],
                "indicators": json.loads(row[5]) if row[5] else [],
                "urls_analyzed": json.loads(row[6]) if row[6] else [],
                "analyzed_at": row[7],
                "anomaly_score": row[8],
                "false_positive_reported": bool(row[9]),
                "false_positive_reason": row[10],
            })
        return results

    except Exception as e:
        print(f"[Storage] Failed to read history: {e}")
        return []


def close_db():
    """Close the SQLite connection on shutdown."""
    global _db

    if _db is not None:
        try:
            with _db_lock:
                _db.close()
            print("[Storage] SQLite connection closed")
        except Exception as e:
            print(f"[Storage] Error closing database: {e}")
        finally:
            _db = None
            _db_initialized = False

"""SQLite database connection and schema initialization."""

import sqlite3
from pathlib import Path
from contextlib import contextmanager

from ..config import DATABASE_PATH


def init_db(db_path: str = None) -> None:
    """Initialize database tables and indexes if they do not exist."""
    from .. import config
    target_path = db_path or config.DATABASE_PATH
    path = Path(target_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                redacted_text TEXT,
                url TEXT,
                verdict TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                summary TEXT,
                top_category TEXT,
                rule_flags_json TEXT,
                text_ml_prob REAL,
                url_ml_prob REAL,
                explanation_en_json TEXT,
                explanation_hi_json TEXT
            );
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_created_at
            ON scan_history (created_at DESC);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_verdict
            ON scan_history (verdict);
        """)
        conn.commit()


@contextmanager
def get_db_connection(db_path: str = None):
    """Context manager for obtaining a thread-safe SQLite connection."""
    from .. import config
    target_path = db_path or config.DATABASE_PATH
    conn = sqlite3.connect(target_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

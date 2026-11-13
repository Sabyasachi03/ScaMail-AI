"""Database package for SQLite scan history and analytics."""

from .database import get_db_connection, init_db
from .crud import insert_scan_record, get_scan_history, get_scan_statistics

__all__ = [
    "get_db_connection",
    "init_db",
    "insert_scan_record",
    "get_scan_history",
    "get_scan_statistics",
]

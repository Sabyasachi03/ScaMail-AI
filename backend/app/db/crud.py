"""Database CRUD operations for scan history and dashboard statistics."""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from .database import get_db_connection


def insert_scan_record(data: Dict[str, Any]) -> str:
    """Inserts a completed scan record into the database."""
    created_ts = data.get("created_at") or (datetime.now(timezone.utc).isoformat())
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_history (
                id, created_at, redacted_text, url, verdict,
                risk_score, risk_level, summary, top_category,
                rule_flags_json, text_ml_prob, url_ml_prob,
                explanation_en_json, explanation_hi_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["id"],
                created_ts,
                data.get("redacted_text"),
                data.get("url"),
                data["verdict"],
                float(data["risk_score"]),
                data["risk_level"],
                data.get("summary", ""),
                data.get("top_category"),
                json.dumps(data.get("rule_flags", [])),
                data.get("text_ml_prob"),
                data.get("url_ml_prob"),
                json.dumps(data.get("explanation_en")) if data.get("explanation_en") else None,
                json.dumps(data.get("explanation_hi")) if data.get("explanation_hi") else None,
            ),
        )
        conn.commit()
    return data["id"]


def get_scan_history(
    limit: int = 20,
    offset: int = 0,
    verdict: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves paginated scan history."""
    limit = max(1, min(100, limit))
    offset = max(0, offset)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if verdict:
            cursor.execute(
                "SELECT COUNT(*) FROM scan_history WHERE verdict = ?",
                (verdict,),
            )
            total = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT id, created_at, redacted_text, url, verdict,
                       risk_score, risk_level, top_category
                FROM scan_history
                WHERE verdict = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (verdict, limit, offset),
            )
        else:
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            total = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT id, created_at, redacted_text, url, verdict,
                       risk_score, risk_level, top_category
                FROM scan_history
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )

        rows = cursor.fetchall()

    items: List[Dict[str, Any]] = []
    for r in rows:
        text = r["redacted_text"] or ""
        snippet = (text[:75] + "...") if len(text) > 75 else (text or None)
        items.append({
            "scan_id": r["id"],
            "timestamp": r["created_at"],
            "redacted_text_snippet": snippet,
            "url": r["url"],
            "verdict": r["verdict"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "top_category": r["top_category"],
        })

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


def get_scan_statistics() -> Dict[str, Any]:
    """Aggregates summary statistics for dashboard display."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Total scans and average risk score
        cursor.execute("SELECT COUNT(*), AVG(risk_score) FROM scan_history")
        row = cursor.fetchone()
        total_scans = row[0] or 0
        avg_score = round(float(row[1] or 0.0), 1)

        # Verdict breakdown
        cursor.execute(
            """
            SELECT verdict, COUNT(*) 
            FROM scan_history 
            GROUP BY verdict
            """
        )
        verdict_counts = {r[0]: r[1] for r in cursor.fetchall()}

        # Top threat categories
        cursor.execute(
            """
            SELECT top_category, COUNT(*) as cnt
            FROM scan_history
            WHERE top_category IS NOT NULL AND top_category != ''
            GROUP BY top_category
            ORDER BY cnt DESC
            LIMIT 6
            """
        )
        top_cats = [{"category": r[0], "count": r[1]} for r in cursor.fetchall()]

    return {
        "total_scans": total_scans,
        "verdict_breakdown": {
            "safe": verdict_counts.get("Safe", 0),
            "suspicious": verdict_counts.get("Suspicious", 0),
            "likely_scam": verdict_counts.get("Likely Scam", 0),
        },
        "top_threat_categories": top_cats,
        "average_risk_score": avg_score,
    }

"""Unit tests for SQLite database operations and analytics."""

import os
import tempfile
import unittest
from backend.app.db.database import init_db
from backend.app.db.crud import insert_scan_record, get_scan_history, get_scan_statistics


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()
        # Patch config db path
        from backend.app import config
        config.DATABASE_PATH = self.db_path
        init_db(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_insert_and_retrieve_history(self):
        scan_data = {
            "id": "test-uuid-1",
            "created_at": "2026-11-13T12:00:00Z",
            "redacted_text": "Your account is blocked. Call [PHONE_REDACTED]",
            "url": "http://phishing.example.com",
            "verdict": "Likely Scam",
            "risk_score": 88.5,
            "risk_level": "high",
            "summary": "Urgent bank threat",
            "top_category": "urgency",
            "rule_flags": [{"rule": "ACCOUNT_SUSPENSION_THREAT"}],
            "text_ml_prob": 0.95,
            "url_ml_prob": 0.89,
        }
        rec_id = insert_scan_record(scan_data)
        self.assertEqual(rec_id, "test-uuid-1")

        history = get_scan_history(limit=10, offset=0)
        self.assertEqual(history["total"], 1)
        self.assertEqual(len(history["items"]), 1)
        self.assertEqual(history["items"][0]["scan_id"], "test-uuid-1")
        self.assertEqual(history["items"][0]["verdict"], "Likely Scam")

    def test_statistics(self):
        # Insert safe record
        insert_scan_record({
            "id": "safe-1",
            "verdict": "Safe",
            "risk_score": 10.0,
            "risk_level": "low",
            "top_category": None,
        })
        # Insert scam record
        insert_scan_record({
            "id": "scam-1",
            "verdict": "Likely Scam",
            "risk_score": 90.0,
            "risk_level": "high",
            "top_category": "credential_theft",
        })

        stats = get_scan_statistics()
        self.assertEqual(stats["total_scans"], 2)
        self.assertEqual(stats["verdict_breakdown"]["safe"], 1)
        self.assertEqual(stats["verdict_breakdown"]["likely_scam"], 1)
        self.assertEqual(stats["average_risk_score"], 50.0)


if __name__ == "__main__":
    unittest.main()

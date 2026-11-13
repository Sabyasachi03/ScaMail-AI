"""Unit tests for the end-to-end DetectionPipeline."""

import os
import tempfile
import unittest
from backend.app.services.pipeline import DetectionPipeline
from backend.app.db.database import init_db


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()
        from backend.app import config
        config.DATABASE_PATH = self.db_path
        init_db(self.db_path)
        self.pipeline = DetectionPipeline()

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_pipeline_with_redaction_and_rules(self):
        text = "URGENT: Your SBI account is blocked. Verify OTP 738291 at http://sbi-fake.com or call 9876543210 immediately."
        res = self.pipeline.process(text=text, url="http://sbi-fake.com")

        # 1. Output structure
        self.assertIn("scan_id", res)
        self.assertIn("risk_score", res)
        self.assertIn("verdict", res)
        self.assertEqual(res["verdict"], "Likely Scam")
        self.assertGreaterEqual(res["risk_score"], 70.0)

        # 2. PII Redaction check
        self.assertNotIn("9876543210", res["redacted_text"])
        self.assertIn("[PHONE_REDACTED]", res["redacted_text"])
        self.assertNotIn("738291", res["redacted_text"])
        self.assertIn("[OTP_REDACTED]", res["redacted_text"])

        # 3. Rule detections
        self.assertTrue(res["detections"]["rules"]["triggered"])
        self.assertGreater(len(res["detections"]["rules"]["flags"]), 0)

        # 4. Bilingual explanation
        self.assertIsNotNone(res["explanation"]["en"])
        self.assertIsNotNone(res["explanation"]["hi"])
        self.assertGreater(len(res["explanation"]["en"]["actions"]), 0)
        self.assertGreater(len(res["explanation"]["hi"]["actions"]), 0)

    def test_pipeline_benign_message(self):
        text = "Meeting at 4 PM in conference room B. Please bring your project notebook."
        res = self.pipeline.process(text=text)

        self.assertEqual(res["verdict"], "Safe")
        self.assertLess(res["risk_score"], 35.0)
        self.assertFalse(res["detections"]["rules"]["triggered"])

    def test_pipeline_empty_raises_error(self):
        with self.assertRaises(ValueError):
            self.pipeline.process(text="", url=None)


if __name__ == "__main__":
    unittest.main()

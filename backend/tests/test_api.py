"""Tests for pipeline inputs, edge cases, and schema validations."""

import os
import tempfile
import unittest
from backend.app.services.pipeline import DetectionPipeline
from backend.app.db.database import init_db
from backend.app.schemas import ScanRequest, ScanResponse


class TestPipelineEdgeCases(unittest.TestCase):
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

    def test_url_only_scan(self):
        url = "http://sbi-secure-kyc-update.com/login"
        res = self.pipeline.process(url=url)
        self.assertIn("scan_id", res)
        self.assertEqual(res["url"], url)
        self.assertIsNone(res["redacted_text"])
        self.assertTrue(res["detections"]["rules"]["triggered"])
        self.assertGreaterEqual(res["risk_score"], 35.0)

    def test_hindi_language_preference(self):
        text = "Congratulations! You won Rs. 10 Lakhs. Claim immediately."
        res = self.pipeline.process(text=text, language_preference="hi")
        self.assertIsNone(res["explanation"]["en"])
        self.assertIsNotNone(res["explanation"]["hi"])
        self.assertIn("जोखिम", res["explanation"]["hi"]["title"])

    def test_english_language_preference(self):
        text = "Congratulations! You won Rs. 10 Lakhs. Claim immediately."
        res = self.pipeline.process(text=text, language_preference="en")
        self.assertIsNotNone(res["explanation"]["en"])
        self.assertIsNone(res["explanation"]["hi"])
        self.assertIn("Risk", res["explanation"]["en"]["title"])

    def test_pydantic_schema_validation(self):
        # Validate that pipeline output conforms directly to ScanResponse schema
        text = "URGENT: Your account is suspended. Update KYC now at http://fake.com"
        res = self.pipeline.process(text=text, url="http://fake.com")
        validated = ScanResponse(**res)
        self.assertEqual(validated.scan_id, res["scan_id"])
        self.assertEqual(validated.verdict, res["verdict"])


if __name__ == "__main__":
    unittest.main()

"""Unit tests for Detection Fusion logic and risk score calculations."""

import unittest
from backend.app.fusion.score_calculator import FusionCalculator


class TestFusionCalculator(unittest.TestCase):
    def test_benign_safe_verdict(self):
        rule_res = {"raw_rule_score": 0.0, "has_critical": False}
        res = FusionCalculator.calculate_score(
            rule_result=rule_res,
            text_ml_prob=0.05,
            url_ml_prob=0.02,
            has_text=True,
            has_url=True,
        )
        self.assertEqual(res["verdict"], "Safe")
        self.assertEqual(res["risk_level"], "low")
        self.assertLess(res["risk_score"], 35.0)

    def test_suspicious_verdict(self):
        # Medium rule score + moderate ML
        rule_res = {"raw_rule_score": 0.35, "has_critical": False}
        res = FusionCalculator.calculate_score(
            rule_result=rule_res,
            text_ml_prob=0.60,
            has_text=True,
            has_url=False,
        )
        self.assertEqual(res["verdict"], "Suspicious")
        self.assertEqual(res["risk_level"], "medium")
        self.assertGreaterEqual(res["risk_score"], 35.0)
        self.assertLess(res["risk_score"], 70.0)

    def test_likely_scam_verdict(self):
        # High text prob + high url prob
        rule_res = {"raw_rule_score": 0.60, "has_critical": False}
        res = FusionCalculator.calculate_score(
            rule_result=rule_res,
            text_ml_prob=0.95,
            url_ml_prob=0.98,
            has_text=True,
            has_url=True,
        )
        self.assertEqual(res["verdict"], "Likely Scam")
        self.assertEqual(res["risk_level"], "high")
        self.assertGreaterEqual(res["risk_score"], 70.0)

    def test_critical_rule_floor_override(self):
        # Even if ML somehow returns 0.0, critical rule (like OTP request) forces minimum 75.0
        rule_res = {"raw_rule_score": 0.45, "has_critical": True}
        res = FusionCalculator.calculate_score(
            rule_result=rule_res,
            text_ml_prob=0.0,
            has_text=True,
            has_url=False,
        )
        self.assertEqual(res["verdict"], "Likely Scam")
        self.assertGreaterEqual(res["risk_score"], 75.0)
        self.assertIn("CRITICAL_RULE_FLOOR_APPLIED", res["applied_overrides"])

    def test_high_ml_floor_override(self):
        # High ML confidence enforces minimum 70.0
        rule_res = {"raw_rule_score": 0.0, "has_critical": False}
        res = FusionCalculator.calculate_score(
            rule_result=rule_res,
            text_ml_prob=0.92,
            has_text=True,
            has_url=False,
        )
        self.assertEqual(res["verdict"], "Likely Scam")
        self.assertGreaterEqual(res["risk_score"], 70.0)


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the heuristic RuleEngine."""

import unittest
from backend.app.rules.rule_engine import RuleEngine


class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine()

    def test_empty_input(self):
        result = self.engine.evaluate(text="", url="")
        self.assertFalse(result["triggered"])
        self.assertEqual(result["score_contribution"], 0.0)
        self.assertEqual(len(result["flags"]), 0)

    def test_critical_otp_request(self):
        text = "Dear user, share your 6-digit OTP immediately to verify transaction."
        result = self.engine.evaluate(text=text)
        self.assertTrue(result["triggered"])
        self.assertTrue(result["has_critical"])
        rule_ids = [f["rule"] for f in result["flags"]]
        self.assertIn("CREDENTIAL_OTP_REQUEST", rule_ids)
        self.assertGreater(result["raw_rule_score"], 0.4)

    def test_remote_access_hijack(self):
        text = "Kindly install AnyDesk app to fix your banking app problem immediately."
        result = self.engine.evaluate(text=text)
        self.assertTrue(result["triggered"])
        self.assertTrue(result["has_critical"])
        rule_ids = [f["rule"] for f in result["flags"]]
        self.assertIn("REMOTE_ACCESS_APP", rule_ids)

    def test_malicious_apk_download(self):
        text = "Update your YONO bank app by downloading this apk file: http://yono-update.com/app.apk"
        result = self.engine.evaluate(text=text)
        self.assertTrue(result["triggered"])
        rule_ids = [f["rule"] for f in result["flags"]]
        self.assertIn("MALICIOUS_APK_DOWNLOAD", rule_ids)

    def test_electricity_bill_threat(self):
        text = "Dear customer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill."
        result = self.engine.evaluate(text=text)
        self.assertTrue(result["triggered"])
        rule_ids = [f["rule"] for f in result["flags"]]
        self.assertIn("ELECTRICITY_BILL_THREAT", rule_ids)

    def test_lottery_prize_lure(self):
        text = "Congratulations! You have won Rs. 25,00,000 in KBC lottery. Claim your reward now."
        result = self.engine.evaluate(text=text)
        self.assertTrue(result["triggered"])
        rule_ids = [f["rule"] for f in result["flags"]]
        self.assertIn("LOTTERY_OR_CASH_PRIZE", rule_ids)

    def test_url_shortener(self):
        url = "https://bit.ly/3x8AbCd"
        result = self.engine.evaluate(url=url)
        self.assertTrue(result["triggered"])
        rule_ids = [f["rule"] for f in result["flags"]]
        self.assertIn("URL_SHORTENER_DETECTED", rule_ids)

    def test_benign_message(self):
        text = "Hey Dad, what time will dinner be ready tonight? I'm heading home."
        result = self.engine.evaluate(text=text)
        self.assertFalse(result["triggered"])
        self.assertEqual(result["raw_rule_score"], 0.0)


if __name__ == "__main__":
    unittest.main()

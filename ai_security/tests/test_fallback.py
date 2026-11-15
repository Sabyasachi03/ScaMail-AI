"""Tests for deterministic fallback templates."""

import pytest
from ai_security.fallback_templates import get_fallback_explanation


class TestFallbackDeterminism:
    """Fallback must produce identical output for identical inputs."""

    def test_same_input_same_output(self):
        args = dict(verdict="Likely Scam", risk_score=90.0,
                    rule_flags=[{"category": "credential_theft", "rule": "CREDENTIAL_OTP_REQUEST", "severity": "critical"}])
        result1 = get_fallback_explanation(**args)
        result2 = get_fallback_explanation(**args)
        assert result1 == result2


class TestCategorySelection:
    """Correct template selected for each threat category."""

    def test_bank_kyc(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=85.0,
            rule_flags=[{"category": "impersonation", "rule": "BANK_IMPERSONATION", "severity": "medium"}],
        )
        assert "KYC" in result["en"]["title"] or "Impersonation" in result["en"]["title"]

    def test_otp_credential(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=90.0,
            rule_flags=[{"category": "credential_theft", "rule": "CREDENTIAL_OTP_REQUEST", "severity": "critical"}],
        )
        assert "OTP" in result["en"]["title"] or "Credential" in result["en"]["title"]

    def test_lottery_prize(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=80.0,
            rule_flags=[{"category": "financial_lure", "rule": "LOTTERY_OR_CASH_PRIZE", "severity": "high"}],
        )
        assert "Lottery" in result["en"]["title"] or "Prize" in result["en"]["title"]

    def test_apk_remote_access(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=85.0,
            rule_flags=[{"category": "malicious_tool", "rule": "REMOTE_ACCESS_APP", "severity": "critical"}],
        )
        assert "Remote" in result["en"]["title"] or "App" in result["en"]["title"] or "Malicious" in result["en"]["title"]

    def test_phishing_url(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=80.0,
            rule_flags=[{"category": "url_anomaly", "rule": "IP_HOST_DETECTED", "severity": "high"}],
        )
        assert "Phishing" in result["en"]["title"] or "URL" in result["en"]["title"]

    def test_generic_scam(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=75.0,
            rule_flags=[],
        )
        assert "Scam" in result["en"]["title"] or "Risk" in result["en"]["title"]


class TestVerdictLevels:
    """Correct templates for each verdict level."""

    def test_safe(self):
        result = get_fallback_explanation(verdict="Safe", risk_score=10.0)
        assert "Low Risk" in result["en"]["title"]

    def test_suspicious(self):
        result = get_fallback_explanation(verdict="Suspicious", risk_score=50.0)
        assert "Medium Risk" in result["en"]["title"] or "Suspicious" in result["en"]["title"]

    def test_likely_scam(self):
        result = get_fallback_explanation(verdict="Likely Scam", risk_score=85.0)
        assert "High Risk" in result["en"]["title"]


class TestBilingualOutput:
    """Both English and Hindi must be present."""

    def test_both_languages(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=90.0,
            rule_flags=[{"category": "credential_theft", "rule": "CREDENTIAL_OTP_REQUEST", "severity": "critical"}],
        )
        assert "en" in result
        assert "hi" in result
        assert result["en"]["title"]
        assert result["hi"]["title"]

    def test_en_only(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=90.0,
            language_preference="en",
        )
        assert "en" in result
        assert "hi" not in result

    def test_hi_only(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=90.0,
            language_preference="hi",
        )
        assert "hi" in result
        assert "en" not in result


class TestHelplinePresence:
    """Helpline numbers should be present in high-risk templates."""

    def test_helpline_1930(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=90.0,
            rule_flags=[{"category": "credential_theft", "rule": "CREDENTIAL_OTP_REQUEST", "severity": "critical"}],
        )
        actions_text = " ".join(result["en"]["actions"])
        assert "1930" in actions_text

    def test_cybercrime_gov(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=90.0,
        )
        actions_text = " ".join(result["en"]["actions"])
        assert "cybercrime.gov.in" in actions_text

    def test_chakshu_sanchar_saathi(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=90.0,
        )
        actions_text = " ".join(result["en"]["actions"])
        assert "sancharsaathi.gov.in" in actions_text or "Chakshu" in actions_text

    def test_hindi_helpline(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=90.0,
        )
        actions_text = " ".join(result["hi"]["actions"])
        assert "1930" in actions_text


class TestActionStructure:
    """Each explanation must have valid structure."""

    def test_action_count(self):
        result = get_fallback_explanation(
            verdict="Likely Scam", risk_score=90.0,
            rule_flags=[{"category": "credential_theft", "rule": "CREDENTIAL_OTP_REQUEST", "severity": "critical"}],
        )
        assert 2 <= len(result["en"]["actions"]) <= 5
        assert 2 <= len(result["hi"]["actions"]) <= 5

    def test_title_not_empty(self):
        for verdict in ("Safe", "Suspicious", "Likely Scam"):
            result = get_fallback_explanation(verdict=verdict, risk_score=50.0)
            for lang in ("en", "hi"):
                assert result[lang]["title"]
                assert result[lang]["description"]

"""Tests verifying backend compatibility and interface contracts.

Tests that ai_security exports match backend expectations:
- backend/app/services/security_client.py imports redact_pii and generate_explanation
- generate_explanation works with the backend call signature
- Output validates against backend/app/schemas.py (ActionGuide, BilingualExplanation)
- llm_status() values match health endpoint expectations
"""

import pytest
from ai_security import (
    redact_pii,
    redact_text,
    redact_url_for_storage,
    RedactionResult,
    detect_prompt_injection,
    generate_explanation,
    llm_status,
)


class TestPublicExports:
    """Test all expected public names are exported."""

    def test_redact_pii_exported(self):
        assert callable(redact_pii)

    def test_redact_text_exported(self):
        assert callable(redact_text)

    def test_redact_url_for_storage_exported(self):
        assert callable(redact_url_for_storage)

    def test_detect_prompt_injection_exported(self):
        assert callable(detect_prompt_injection)

    def test_generate_explanation_exported(self):
        assert callable(generate_explanation)

    def test_llm_status_exported(self):
        assert callable(llm_status)

    def test_redaction_result_type_exported(self):
        assert isinstance(RedactionResult("test", []), RedactionResult)


class TestRedactPiiSignature:
    """Backend expects redact_pii(text: str) -> str."""

    def test_redact_pii_returns_str(self):
        res = redact_pii("Call +91 9876543210 with OTP 1234")
        assert isinstance(res, str)
        assert "[PHONE_REDACTED]" in res
        assert "[OTP_REDACTED]" in res

    def test_redact_pii_none_or_empty(self):
        assert redact_pii("") == ""
        assert redact_pii(None) == ""


class TestLLMStatusHealthEndpoint:
    """Backend health check expects llm_service to be 'online' or 'fallback_ready'."""

    def test_llm_status_values(self):
        status = llm_status()
        assert status in ("online", "fallback_ready")


class TestBackendExplanationSignature:
    """Backend calls generate_explanation with positional and keyword arguments."""

    def test_backend_positional_call(self):
        rule_flags = [{"category": "impersonation", "rule": "BANK_IMPERSONATION", "severity": "medium"}]
        url_flags = ["suspicious_keywords"]
        res = generate_explanation("Likely Scam", 85.0, rule_flags, url_flags)
        assert isinstance(res, dict)
        assert "en" in res
        assert "hi" in res
        assert res["en"]["title"]
        assert len(res["en"]["actions"]) >= 2

    def test_backend_keyword_call(self):
        rule_flags = [{"category": "credential_theft", "rule": "CREDENTIAL_OTP_REQUEST", "severity": "critical"}]
        url_flags = []
        res = generate_explanation(
            verdict="Likely Scam",
            risk_score=95.0,
            rule_flags=rule_flags,
            url_flags=url_flags,
        )
        assert "en" in res
        assert "hi" in res

    def test_richer_keyword_call(self):
        """Supports richer keyword-only interface without breaking."""
        res = generate_explanation(
            verdict="Suspicious",
            risk_score=55.0,
            risk_level="medium",
            redacted_text="Verify at http://test.xyz",
            detections={"rules": {"flags": []}, "url_ml": {"flags": ["not_https"]}},
            language_preference="both",
        )
        assert "en" in res
        assert "hi" in res
        assert "explanation" in res
        assert "meta" in res


class TestBackendSchemaValidation:
    """Validate explanation output directly against backend schemas."""

    def test_validates_against_backend_schemas(self):
        try:
            from backend.app.schemas import BilingualExplanation, ActionGuide
        except ImportError:
            pytest.skip("backend.app.schemas could not be imported")

        for verdict, score, flags in [
            ("Safe", 10.0, []),
            ("Suspicious", 50.0, [{"category": "urgency", "rule": "TIME_PRESSURE_DEADLINE", "severity": "high"}]),
            ("Likely Scam", 90.0, [{"category": "credential_theft", "rule": "CREDENTIAL_OTP_REQUEST", "severity": "critical"}]),
        ]:
            exp = generate_explanation(verdict=verdict, risk_score=score, rule_flags=flags, url_flags=[])
            # Must construct cleanly
            bilingual = BilingualExplanation(**exp)
            assert bilingual.en is not None
            assert isinstance(bilingual.en, ActionGuide)
            assert bilingual.en.title
            assert bilingual.en.description
            assert 2 <= len(bilingual.en.actions) <= 5

            assert bilingual.hi is not None
            assert isinstance(bilingual.hi, ActionGuide)
            assert bilingual.hi.title
            assert bilingual.hi.description
            assert 2 <= len(bilingual.hi.actions) <= 5


class TestBackendSecurityClientIntegration:
    """Direct integration test with backend SecurityClient wrapper."""

    def test_security_client_uses_ai_security(self):
        try:
            from backend.app.services.security_client import SecurityClient
        except ImportError:
            pytest.skip("backend.app.services.security_client could not be imported")

        client = SecurityClient()
        assert client._external_redactor is not None
        assert client._external_explainer is not None

        # Test redact method
        redacted = client.redact("Call 9876543210 now with OTP 9999")
        assert "[PHONE_REDACTED]" in redacted
        assert "[OTP_REDACTED]" in redacted

        # Test generate_explanation method
        exp = client.generate_explanation(
            verdict="Likely Scam",
            risk_score=92.0,
            rule_flags=[{"category": "impersonation", "rule": "BANK_IMPERSONATION", "severity": "high"}],
            url_flags=[],
            has_text=True,
            has_url=False,
        )
        assert "en" in exp
        assert "hi" in exp
        assert exp["en"]["title"]

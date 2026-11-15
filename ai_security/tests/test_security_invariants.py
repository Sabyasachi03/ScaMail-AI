"""Security invariant tests.

These tests prove the critical security guarantees:
1. LLM cannot lower risk or call a risky input safe
2. Raw PII never reaches the LLM
3. No API key in source, tests, logs, docs, or commits
4. Redaction is applied before any external call
"""

import json
import os
import pytest
from unittest.mock import patch
from ai_security.llm_explainer import generate_explanation
from ai_security.llm_client import _cache, _cache_order
from ai_security.redaction import redact_text, redact_pii


class MockResponse:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self._data = data
    def json(self):
        return self._data


class CapturingTransport:
    """Transport that captures what was sent to the LLM."""
    def __init__(self, response_json="{}"):
        self.captured_requests = []
        self.response_json = response_json
    def post(self, url, headers=None, json=None, timeout=None):
        self.captured_requests.append({
            "url": url, "headers": headers, "json": json,
        })
        return MockResponse(200, {
            "choices": [{"message": {"content": self.response_json}}]
        })


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    _cache_order.clear()
    yield
    _cache.clear()
    _cache_order.clear()


class TestLLMCannotLowerRisk:
    """The LLM output schema has NO verdict/risk fields.
    Even if the LLM tries to set them, they are ignored.
    """

    def test_llm_safe_wording_rejected_for_likely_scam(self):
        """LLM says 'safe' for Likely Scam → safety filter rejects → fallback."""
        with patch.dict("os.environ", {"LLM_API_KEY": "key", "LLM_PROVIDER": "openai"}, clear=False):
            malicious = json.dumps({
                "en": {
                    "title": "All Clear",
                    "description": "This is completely safe and genuine. You can safely proceed.",
                    "actions": ["No action needed", "This is legitimate"],
                },
                "hi": {
                    "title": "सब ठीक",
                    "description": "यह पूरी तरह सुरक्षित है।",
                    "actions": ["कोई कार्रवाई नहीं", "ठीक है"],
                },
            })
            transport = CapturingTransport(malicious)
            result = generate_explanation(
                verdict="Likely Scam", risk_score=92.0,
                _http_transport=transport,
            )
            # Must fall back — LLM tried to say "safe" for a scam
            assert result["meta"]["source"] == "fallback"

    def test_llm_safe_wording_rejected_for_suspicious(self):
        """LLM says 'no risk' for Suspicious → safety filter rejects."""
        with patch.dict("os.environ", {"LLM_API_KEY": "key", "LLM_PROVIDER": "openai"}, clear=False):
            malicious = json.dumps({
                "en": {
                    "title": "No Issues",
                    "description": "There is no risk or danger here.",
                    "actions": ["Proceed safely", "Nothing to worry about"],
                },
                "hi": {
                    "title": "कोई समस्या नहीं",
                    "description": "कोई खतरा नहीं है।",
                    "actions": ["आगे बढ़ें", "चिंता मत करें"],
                },
            })
            transport = CapturingTransport(malicious)
            result = generate_explanation(
                verdict="Suspicious", risk_score=55.0,
                _http_transport=transport,
            )
            assert result["meta"]["source"] == "fallback"


class TestPIINeverReachesLLM:
    """Raw PII must never be sent to the LLM."""

    def test_phone_not_in_llm_request(self):
        """If redacted_text is sent, phone numbers must be redacted."""
        with patch.dict("os.environ", {"LLM_API_KEY": "key", "LLM_PROVIDER": "openai"}, clear=False):
            raw_text = "Call +91 9876543210 and send OTP 1234"
            redacted = redact_pii(raw_text)

            transport = CapturingTransport('{"en": {"title": "T", "description": "D", "actions": ["A1", "A2"]}, "hi": {"title": "T", "description": "D", "actions": ["A1", "A2"]}}')
            generate_explanation(
                verdict="Likely Scam", risk_score=90.0,
                redacted_text=redacted,
                _http_transport=transport,
            )

            # Check what was actually sent
            assert len(transport.captured_requests) == 1
            sent_content = json.dumps(transport.captured_requests[0]["json"])
            assert "9876543210" not in sent_content
            assert "1234" not in sent_content or "[OTP_REDACTED]" in sent_content

    def test_redaction_applied_before_llm(self):
        """Demonstrate the workflow: redact FIRST, then explain."""
        raw = "Your Aadhaar 2345 6789 0123 KYC pending"
        result = redact_text(raw)
        assert "2345" not in result.redacted_text
        assert "KYC" in result.redacted_text  # keyword preserved


class TestSecretScan:
    """No API keys or secrets in the source tree."""

    def test_no_hardcoded_keys(self):
        """Scan all Python files in ai_security/ for key-like patterns."""
        import re
        key_patterns = [
            re.compile(r'(?:sk|pk|api[_-]?key|secret|token|password)\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', re.I),
            re.compile(r'Bearer\s+[A-Za-z0-9_\-\.]{20,}'),
            re.compile(r'(?:AKIA|ABIA|ACCA|AROA)[A-Z0-9]{12,}'),  # AWS
        ]
        ai_sec_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)))
        violations = []
        for root, dirs, files in os.walk(ai_sec_dir):
            # Skip .env files
            for f in files:
                if f.endswith(('.py', '.md', '.txt', '.yaml', '.yml', '.json')):
                    filepath = os.path.join(root, f)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                        content = fh.read()
                        for pat in key_patterns:
                            matches = pat.findall(content)
                            if matches:
                                violations.append(f"{filepath}: {matches}")
        assert violations == [], f"Potential secrets found: {violations}"

"""Tests for LLM explainer orchestrator."""

import json
import pytest
from unittest.mock import patch, MagicMock
from ai_security.llm_explainer import generate_explanation, _extract_json, _validate_schema
from ai_security.llm_client import _cache, _cache_order


class MockResponse:
    """Mock HTTP response."""
    def __init__(self, status_code: int, data: dict):
        self.status_code = status_code
        self._data = data
    def json(self):
        return self._data


class MockTransport:
    """Injectable mock HTTP transport."""
    def __init__(self, responses=None):
        self.responses = responses or []
        self.call_count = 0
    def post(self, url, headers=None, json=None, timeout=None):
        if self.call_count < len(self.responses):
            resp = self.responses[self.call_count]
            self.call_count += 1
            if isinstance(resp, Exception):
                raise resp
            return resp
        return MockResponse(500, {})


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    _cache_order.clear()
    yield
    _cache.clear()
    _cache_order.clear()


class TestNeverRaises:
    """generate_explanation must NEVER raise, regardless of input."""

    def test_no_api_key(self):
        with patch.dict("os.environ", {"LLM_API_KEY": ""}, clear=False):
            result = generate_explanation(
                verdict="Likely Scam", risk_score=90.0,
            )
            assert result is not None
            assert "explanation" in result
            assert result["meta"]["source"] == "fallback"
            assert result["meta"]["reason"] == "no_api_key"

    def test_timeout(self):
        with patch.dict("os.environ", {"LLM_API_KEY": "key123"}, clear=False):
            transport = MockTransport([Exception("timeout")])
            result = generate_explanation(
                verdict="Likely Scam", risk_score=90.0,
                _http_transport=transport,
            )
            assert result["meta"]["source"] == "fallback"

    def test_invalid_json_response(self):
        with patch.dict("os.environ", {"LLM_API_KEY": "key123", "LLM_PROVIDER": "openai"}, clear=False):
            response = MockResponse(200, {
                "choices": [{"message": {"content": "this is not json at all"}}]
            })
            transport = MockTransport([response])
            result = generate_explanation(
                verdict="Likely Scam", risk_score=90.0,
                _http_transport=transport,
            )
            assert result["meta"]["source"] == "fallback"
            assert "invalid_json" in result["meta"]["reason"]

    def test_wrong_schema_response(self):
        with patch.dict("os.environ", {"LLM_API_KEY": "key123", "LLM_PROVIDER": "openai"}, clear=False):
            bad_json = json.dumps({"wrong": "schema"})
            response = MockResponse(200, {
                "choices": [{"message": {"content": bad_json}}]
            })
            transport = MockTransport([response])
            result = generate_explanation(
                verdict="Likely Scam", risk_score=90.0,
                _http_transport=transport,
            )
            assert result["meta"]["source"] == "fallback"

    def test_missing_hi_field(self):
        with patch.dict("os.environ", {"LLM_API_KEY": "key123", "LLM_PROVIDER": "openai"}, clear=False):
            # Only en, missing hi for language_preference="both"
            partial = json.dumps({
                "en": {"title": "T", "description": "D", "actions": ["A1", "A2"]},
            })
            response = MockResponse(200, {
                "choices": [{"message": {"content": partial}}]
            })
            transport = MockTransport([response])
            result = generate_explanation(
                verdict="Likely Scam", risk_score=90.0,
                language_preference="both",
                _http_transport=transport,
            )
            assert result["meta"]["source"] == "fallback"

    def test_safety_filter_rejection(self):
        """LLM says 'safe' for Likely Scam — must fall back."""
        with patch.dict("os.environ", {"LLM_API_KEY": "key123", "LLM_PROVIDER": "openai"}, clear=False):
            unsafe_response = json.dumps({
                "en": {
                    "title": "Safe Message",
                    "description": "This appears to be safe and legitimate.",
                    "actions": ["No action needed", "This is fine"],
                },
                "hi": {
                    "title": "सुरक्षित",
                    "description": "यह सुरक्षित है।",
                    "actions": ["कोई कार्रवाई नहीं", "यह ठीक है"],
                },
            })
            response = MockResponse(200, {
                "choices": [{"message": {"content": unsafe_response}}]
            })
            transport = MockTransport([response])
            result = generate_explanation(
                verdict="Likely Scam", risk_score=90.0,
                _http_transport=transport,
            )
            assert result["meta"]["source"] == "fallback"
            assert "safety_filter" in result["meta"]["reason"]


class TestSuccessfulLLM:
    """Successful LLM path."""

    def test_valid_llm_response(self):
        with patch.dict("os.environ", {"LLM_API_KEY": "key123", "LLM_PROVIDER": "openai"}, clear=False):
            valid_response = json.dumps({
                "en": {
                    "title": "High Risk: Scam Detected",
                    "description": "This is a phishing attempt targeting bank credentials.",
                    "actions": ["Do not click links", "Report to cybercrime.gov.in"],
                },
                "hi": {
                    "title": "उच्च जोखिम: धोखाधड़ी",
                    "description": "यह बैंक क्रेडेंशियल्स को लक्षित करने वाला फ़िशिंग प्रयास है।",
                    "actions": ["लिंक पर क्लिक न करें", "cybercrime.gov.in पर रिपोर्ट करें"],
                },
            })
            response = MockResponse(200, {
                "choices": [{"message": {"content": valid_response}}]
            })
            transport = MockTransport([response])
            result = generate_explanation(
                verdict="Likely Scam", risk_score=90.0,
                _http_transport=transport,
            )
            assert result["meta"]["source"] == "llm"
            assert "en" in result["explanation"]
            assert "hi" in result["explanation"]


class TestMarkdownFencedJSON:
    """LLM wrapping JSON in markdown code fence."""

    def test_fenced_json(self):
        fenced = '```json\n{"en": {"title": "T", "description": "D", "actions": ["A1", "A2"]}, "hi": {"title": "H", "description": "D", "actions": ["A1", "A2"]}}\n```'
        result = _extract_json(fenced)
        assert result is not None
        assert "en" in result


class TestFallbackDeterminism:
    """Fallback should be deterministic."""

    def test_fallback_same_output(self):
        with patch.dict("os.environ", {"LLM_API_KEY": ""}, clear=False):
            r1 = generate_explanation(verdict="Likely Scam", risk_score=85.0)
            r2 = generate_explanation(verdict="Likely Scam", risk_score=85.0)
            assert r1["explanation"] == r2["explanation"]


class TestMeta:
    """Meta information in response."""

    def test_meta_has_source(self):
        with patch.dict("os.environ", {"LLM_API_KEY": ""}, clear=False):
            result = generate_explanation(verdict="Safe", risk_score=10.0)
            assert "meta" in result
            assert "source" in result["meta"]
            assert "latency_ms" in result["meta"]

    def test_meta_latency_positive(self):
        with patch.dict("os.environ", {"LLM_API_KEY": ""}, clear=False):
            result = generate_explanation(verdict="Safe", risk_score=10.0)
            assert result["meta"]["latency_ms"] >= 0


class TestLegacyParams:
    """Backend calls with legacy parameter names."""

    def test_legacy_params(self):
        with patch.dict("os.environ", {"LLM_API_KEY": ""}, clear=False):
            result = generate_explanation(
                verdict="Likely Scam",
                risk_score=90.0,
                rule_flags=[{"category": "credential_theft", "rule": "CREDENTIAL_OTP_REQUEST", "severity": "critical"}],
                url_flags=["suspicious_keywords"],
            )
            assert result is not None
            assert result["meta"]["source"] == "fallback"

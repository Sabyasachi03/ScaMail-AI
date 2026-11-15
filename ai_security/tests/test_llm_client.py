"""Tests for LLM client — mocked, no real network calls."""

import json
import pytest
from unittest.mock import MagicMock, patch
from ai_security.llm_client import call_llm, is_configured, get_status, _cache, _cache_order


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
    """Clear LLM cache between tests."""
    _cache.clear()
    _cache_order.clear()
    yield
    _cache.clear()
    _cache_order.clear()


class TestNoApiKey:
    """Without API key, client should return None gracefully."""

    @patch.dict("os.environ", {"LLM_API_KEY": ""}, clear=False)
    def test_no_key_returns_none(self):
        result = call_llm("system", "user")
        assert result is None

    @patch.dict("os.environ", {"LLM_API_KEY": ""}, clear=False)
    def test_status_fallback(self):
        assert get_status() == "fallback_ready"


class TestApiKeyConfigured:
    """With API key, client should make calls."""

    @patch.dict("os.environ", {"LLM_API_KEY": "test-key-123", "LLM_PROVIDER": "openai"}, clear=False)
    def test_is_configured(self):
        assert is_configured() is True

    @patch.dict("os.environ", {"LLM_API_KEY": "test-key-123", "LLM_PROVIDER": "openai"}, clear=False)
    def test_status_online(self):
        assert get_status() == "online"


class TestSuccessfulCall:
    """Successful LLM call returns parsed content."""

    @patch.dict("os.environ", {"LLM_API_KEY": "test-key-123", "LLM_PROVIDER": "openai"}, clear=False)
    def test_openai_success(self):
        response = MockResponse(200, {
            "choices": [{"message": {"content": '{"en": {"title": "Test"}}'}}]
        })
        transport = MockTransport([response])
        result = call_llm("system", "user", _http_transport=transport)
        assert result is not None
        assert "Test" in result


class TestTimeout:
    """Timeout should not crash, returns None."""

    @patch.dict("os.environ", {"LLM_API_KEY": "test-key-123", "LLM_PROVIDER": "openai"}, clear=False)
    def test_timeout_returns_none(self):
        transport = MockTransport([Exception("Connection timed out")])
        result = call_llm("system", "user", _http_transport=transport)
        assert result is None


class TestRetryBehavior:
    """At most one retry, no retry on auth errors."""

    @patch.dict("os.environ", {"LLM_API_KEY": "test-key-123", "LLM_PROVIDER": "openai"}, clear=False)
    def test_retry_on_500(self):
        """Should retry once on 500 error."""
        success_response = MockResponse(200, {
            "choices": [{"message": {"content": '{"result": "ok"}'}}]
        })
        transport = MockTransport([MockResponse(500, {}), success_response])
        result = call_llm("system", "user", _http_transport=transport)
        assert result is not None
        assert transport.call_count == 2

    @patch.dict("os.environ", {"LLM_API_KEY": "test-key-123", "LLM_PROVIDER": "openai"}, clear=False)
    def test_no_retry_on_401(self):
        """Should NOT retry on auth error."""
        transport = MockTransport([MockResponse(401, {})])
        result = call_llm("system", "user", _http_transport=transport)
        assert result is None
        assert transport.call_count == 1

    @patch.dict("os.environ", {"LLM_API_KEY": "test-key-123", "LLM_PROVIDER": "openai"}, clear=False)
    def test_no_retry_on_403(self):
        """Should NOT retry on 403."""
        transport = MockTransport([MockResponse(403, {})])
        result = call_llm("system", "user", _http_transport=transport)
        assert result is None
        assert transport.call_count == 1


class TestCache:
    """In-memory cache behavior."""

    @patch.dict("os.environ", {"LLM_API_KEY": "test-key-123", "LLM_PROVIDER": "openai"}, clear=False)
    def test_cache_hit(self):
        """Same inputs should return cached result without new call."""
        response = MockResponse(200, {
            "choices": [{"message": {"content": '{"cached": true}'}}]
        })
        transport = MockTransport([response])

        result1 = call_llm("system", "user", _http_transport=transport)
        result2 = call_llm("system", "user", _http_transport=transport)

        assert result1 == result2
        assert transport.call_count == 1  # Only one actual call

    @patch.dict("os.environ", {"LLM_API_KEY": "test-key-123", "LLM_PROVIDER": "openai"}, clear=False)
    def test_different_inputs_no_cache(self):
        """Different inputs should make separate calls."""
        response1 = MockResponse(200, {
            "choices": [{"message": {"content": '{"first": true}'}}]
        })
        response2 = MockResponse(200, {
            "choices": [{"message": {"content": '{"second": true}'}}]
        })
        transport = MockTransport([response1, response2])

        result1 = call_llm("system", "user1", _http_transport=transport)
        result2 = call_llm("system", "user2", _http_transport=transport)

        assert result1 != result2
        assert transport.call_count == 2

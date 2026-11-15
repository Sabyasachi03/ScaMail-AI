"""Provider-agnostic LLM HTTP client.

Configured entirely by environment variables:
- LLM_PROVIDER: "openai" | "google" | "anthropic" (default: "openai")
- LLM_API_KEY: API key (no default — missing key => fallback)
- LLM_MODEL: model name (default: provider-specific)
- LLM_TIMEOUT_SECONDS: per-request timeout (default: 6)

Properties:
- Temperature 0, JSON output mode
- Overall 8-second budget across attempts
- At most one retry (not on auth errors)
- Small in-memory cache keyed by hash of inputs
- Never raises on failure — returns None
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _try_load_env() -> None:
    """Attempt to load environment variables from .env files if not already present."""
    if "LLM_API_KEY" in os.environ and "LLM_PROVIDER" in os.environ:
        return

    try:
        from dotenv import load_dotenv
        for env_path in [
            Path(__file__).resolve().parent / ".env",
            Path(__file__).resolve().parents[1] / ".env",
            Path.cwd() / ".env",
            Path.cwd() / "ai_security" / ".env",
        ]:
            if env_path.is_file():
                load_dotenv(dotenv_path=env_path)
    except Exception:
        pass

    for candidate in [
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parents[1] / ".env",
    ]:
        if candidate.is_file():
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k not in os.environ and v:
                                os.environ[k] = v
            except Exception:
                pass


# ---------------------------------------------------------------------------
# In-memory LRU-ish cache (bounded)
# ---------------------------------------------------------------------------

_MAX_CACHE_SIZE = 128
_cache: Dict[str, Dict[str, Any]] = {}
_cache_order: list = []


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    """Get from cache, or None."""
    return _cache.get(key)


def _cache_put(key: str, value: Dict[str, Any]) -> None:
    """Put into cache, evicting oldest if over size limit."""
    if key in _cache:
        return
    _cache[key] = value
    _cache_order.append(key)
    while len(_cache_order) > _MAX_CACHE_SIZE:
        old_key = _cache_order.pop(0)
        _cache.pop(old_key, None)


def _make_cache_key(payload: Dict[str, Any]) -> str:
    """Create a deterministic hash key from the request payload."""
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _get_config() -> Dict[str, Any]:
    """Read LLM config from environment variables."""
    _try_load_env()
    provider = os.environ.get("LLM_PROVIDER", "openai").lower()
    api_key = os.environ.get("LLM_API_KEY", "")
    timeout = int(os.environ.get("LLM_TIMEOUT_SECONDS", "6"))

    model_defaults = {
        "openai": "gpt-4o-mini",
        "google": "gemini-1.5-flash",
        "anthropic": "claude-3-haiku-20240307",
    }
    model = os.environ.get("LLM_MODEL", model_defaults.get(provider, "gpt-4o-mini"))

    endpoint_map = {
        "openai": "https://api.openai.com/v1/chat/completions",
        "google": f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "anthropic": "https://api.anthropic.com/v1/messages",
    }

    return {
        "provider": provider,
        "api_key": api_key,
        "model": model,
        "timeout": timeout,
        "endpoint": endpoint_map.get(provider, endpoint_map["openai"]),
    }


# ---------------------------------------------------------------------------
# Request builders per provider
# ---------------------------------------------------------------------------

def _build_openai_request(
    config: Dict[str, Any],
    system_prompt: str,
    user_prompt: str,
) -> Dict[str, Any]:
    """Build OpenAI-compatible request."""
    return {
        "url": config["endpoint"],
        "headers": {
            "Authorization": f"Bearer {config['api_key']}",
            "Content-Type": "application/json",
        },
        "json": {
            "model": config["model"],
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        },
    }


def _build_google_request(
    config: Dict[str, Any],
    system_prompt: str,
    user_prompt: str,
) -> Dict[str, Any]:
    """Build Google Gemini request."""
    return {
        "url": f"{config['endpoint']}?key={config['api_key']}",
        "headers": {"Content-Type": "application/json"},
        "json": {
            "contents": [
                {"parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}
            ],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
            },
        },
    }


def _build_anthropic_request(
    config: Dict[str, Any],
    system_prompt: str,
    user_prompt: str,
) -> Dict[str, Any]:
    """Build Anthropic Claude request."""
    return {
        "url": config["endpoint"],
        "headers": {
            "x-api-key": config["api_key"],
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        },
        "json": {
            "model": config["model"],
            "max_tokens": 1024,
            "temperature": 0,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        },
    }


# ---------------------------------------------------------------------------
# Response parsers per provider
# ---------------------------------------------------------------------------

def _parse_openai_response(data: Dict[str, Any]) -> Optional[str]:
    """Extract text content from OpenAI response."""
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        return None


def _parse_google_response(data: Dict[str, Any]) -> Optional[str]:
    """Extract text content from Google Gemini response."""
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError):
        return None


def _parse_anthropic_response(data: Dict[str, Any]) -> Optional[str]:
    """Extract text content from Anthropic Claude response."""
    try:
        return data["content"][0]["text"]
    except (KeyError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

_BUILDERS = {
    "openai": _build_openai_request,
    "google": _build_google_request,
    "anthropic": _build_anthropic_request,
}

_PARSERS = {
    "openai": _parse_openai_response,
    "google": _parse_google_response,
    "anthropic": _parse_anthropic_response,
}


def is_configured() -> bool:
    """Check if LLM client has a valid API key configured."""
    config = _get_config()
    return bool(config["api_key"])


def call_llm(
    system_prompt: str,
    user_prompt: str,
    *,
    _http_transport: object = None,
) -> Optional[str]:
    """Call the LLM and return the raw text response.

    Args:
        system_prompt: System instructions for the LLM
        user_prompt: User prompt with detection context
        _http_transport: Injectable transport for testing (must have .post())

    Returns:
        Raw text response from the LLM, or None on any failure.
        Never raises.
    """
    config = _get_config()

    if not config["api_key"]:
        logger.info("LLM API key not configured; skipping LLM call")
        return None

    # Check cache
    cache_payload = {"system": system_prompt, "user": user_prompt, "model": config["model"]}
    cache_key = _make_cache_key(cache_payload)
    cached = _cache_get(cache_key)
    if cached is not None:
        logger.debug("LLM cache hit")
        return cached.get("response")

    provider = config["provider"]
    builder = _BUILDERS.get(provider, _BUILDERS["openai"])
    parser = _PARSERS.get(provider, _PARSERS["openai"])

    request = builder(config, system_prompt, user_prompt)
    timeout = config["timeout"]
    overall_deadline = time.monotonic() + 8.0  # 8-second overall budget

    # Import httpx lazily
    try:
        import httpx
    except ImportError:
        logger.warning("httpx not installed; cannot make LLM calls")
        return None

    max_attempts = 2  # 1 initial + 1 retry
    last_error = None

    for attempt in range(max_attempts):
        remaining = overall_deadline - time.monotonic()
        if remaining <= 0:
            logger.warning("LLM overall budget exceeded")
            break

        effective_timeout = min(timeout, remaining)

        try:
            if _http_transport is not None:
                # Use injected transport for testing
                response = _http_transport.post(
                    request["url"],
                    headers=request["headers"],
                    json=request["json"],
                    timeout=effective_timeout,
                )
            else:
                response = httpx.post(
                    request["url"],
                    headers=request["headers"],
                    json=request["json"],
                    timeout=effective_timeout,
                )

            # Auth errors: do not retry
            if response.status_code in (401, 403):
                logger.warning("LLM auth error (%d); not retrying", response.status_code)
                return None

            if response.status_code != 200:
                last_error = f"HTTP {response.status_code}"
                logger.warning("LLM HTTP error: %s (attempt %d)", last_error, attempt + 1)
                continue

            data = response.json()
            text = parser(data)

            if text:
                _cache_put(cache_key, {"response": text})
                return text
            else:
                last_error = "Empty response from parser"
                logger.warning("LLM empty response (attempt %d)", attempt + 1)

        except Exception as e:
            last_error = str(e)
            logger.warning("LLM call failed: %s (attempt %d)", last_error, attempt + 1)

    logger.warning("LLM all attempts exhausted; last error: %s", last_error)
    return None


def get_status() -> str:
    """Return current LLM service status.

    Returns:
        "online" if API key is configured, "fallback_ready" otherwise.
    """
    return "online" if is_configured() else "fallback_ready"

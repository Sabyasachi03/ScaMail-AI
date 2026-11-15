"""Post-validation safety filter for LLM-generated explanations.

Rejects and triggers fallback if:
- The LLM calls a Suspicious/Likely Scam result safe, genuine, or harmless
  (English and Hindi wording)
- Contains HTML/markdown formatting
- Contains URLs or phone numbers not in the allowlist

Allowlisted resources:
- cybercrime.gov.in
- sancharsaathi.gov.in
- 1930 (national cyber helpline)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Allowlisted URLs and phone numbers
# ---------------------------------------------------------------------------

ALLOWED_URLS: Set[str] = {
    "cybercrime.gov.in",
    "sancharsaathi.gov.in",
}

ALLOWED_PHONES: Set[str] = {
    "1930",
}


# ---------------------------------------------------------------------------
# Patterns for "safe" wording that should NOT appear for risky verdicts
# ---------------------------------------------------------------------------

_SAFE_WORDING_EN = re.compile(
    r"(?i)\b(?:(?:this\s+(?:is|appears?|seems?|looks?)\s+(?:to\s+be\s+)?)"
    r"(?:completely\s+|entirely\s+|totally\s+|absolutely\s+)?"
    r"(?:safe|genuine|legitimate|harmless|authentic|trustworthy|not\s+(?:a\s+)?(?:scam|fraud|phishing))|"
    r"(?:no\s+(?:risk|danger|threat|concern|cause\s+for\s+(?:alarm|concern|worry)))|"
    r"(?:you\s+(?:can|may|should)\s+(?:safely|trust|proceed|click|open))\b)"
)

_SAFE_WORDING_HI = re.compile(
    r"(?:(?:सुरक्षित|असली|वैध|हानिरहित|विश्वसनीय)\s*(?:संदेश|है|रूप\s*से|और|हैं|प्रतीत)|"
    r"(?:खतरा|जोखिम|ख़तरा|चिंता)\s*(?:की\s*कोई\s*बात\s*)?(?:नहीं|नही)|"
    r"(?:सुरक्षित|बेझिझक|निसंकोच)\s*(?:रूप\s*से\s*)?(?:क्लिक|खोल|भरोसा|इस्तेमाल)|"
    r"(?:यह\s*(?:संदेश\s*)?)?(?:पूरी\s*तरह\s*(?:से\s*)?)?(?:सुरक्षित|असली|वैध|हानिरहित))"
)


# ---------------------------------------------------------------------------
# HTML / Markdown stripping
# ---------------------------------------------------------------------------

_HTML_TAGS = re.compile(r"<[^>]+>")
_MARKDOWN_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_MARKDOWN_ITALIC = re.compile(r"\*([^*]+)\*")
_MARKDOWN_CODE = re.compile(r"`([^`]+)`")
_MARKDOWN_LINKS = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_MARKDOWN_HEADERS = re.compile(r"^#{1,6}\s+", re.MULTILINE)


def _strip_formatting(text: str) -> str:
    """Remove HTML tags and markdown formatting from text."""
    text = _HTML_TAGS.sub("", text)
    text = _MARKDOWN_BOLD.sub(r"\1", text)
    text = _MARKDOWN_ITALIC.sub(r"\1", text)
    text = _MARKDOWN_CODE.sub(r"\1", text)
    text = _MARKDOWN_LINKS.sub(r"\1", text)
    text = _MARKDOWN_HEADERS.sub("", text)
    return text.strip()


# ---------------------------------------------------------------------------
# URL and phone number filtering
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"(?:https?://[^\s,;)<>\"']+|(?:\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:/[^\s,;)<>\"']*)?))"
)

_PHONE_PATTERN = re.compile(
    r"(?:\+?\d[\d\s\-]{6,14}\d|\b1930\b)"
)


def _filter_urls_phones(text: str) -> str:
    """Remove URLs and phone numbers not in the allowlist."""

    def _url_replacer(m: re.Match) -> str:
        raw_url = m.group(0)
        url_to_parse = raw_url if "://" in raw_url else f"https://{raw_url}"
        try:
            parsed = urlparse(url_to_parse)
            hostname = (parsed.hostname or "").lower()
            for allowed in ALLOWED_URLS:
                if hostname == allowed or hostname.endswith("." + allowed):
                    return raw_url
        except Exception:
            pass
        return ""

    def _phone_replacer(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if digits in ALLOWED_PHONES:
            return m.group(0)
        return ""

    text = _URL_PATTERN.sub(_url_replacer, text)
    text = _PHONE_PATTERN.sub(_phone_replacer, text)
    return text


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class SafetyFilterResult:
    """Result of safety filter validation."""

    __slots__ = ("passed", "reason", "filtered_explanation")

    def __init__(
        self,
        passed: bool,
        reason: Optional[str] = None,
        filtered_explanation: Optional[Dict[str, Any]] = None,
    ):
        self.passed = passed
        self.reason = reason
        self.filtered_explanation = filtered_explanation


def apply_safety_filter(
    explanation: Dict[str, Any],
    verdict: str,
) -> SafetyFilterResult:
    """Validate and sanitize LLM-generated explanation.

    Args:
        explanation: Dict with "en" and/or "hi" keys, each containing
            {title, description, actions[]}
        verdict: The authoritative verdict ("Safe", "Suspicious", "Likely Scam")

    Returns:
        SafetyFilterResult with:
        - passed: True if the explanation passed all checks
        - reason: Why it was rejected (if not passed)
        - filtered_explanation: Sanitized explanation (if passed)
    """
    is_risky = verdict in ("Suspicious", "Likely Scam")

    filtered: Dict[str, Any] = {}

    for lang in ("en", "hi"):
        section = explanation.get(lang)
        if section is None:
            continue

        title = section.get("title", "")
        description = section.get("description", "")
        actions = section.get("actions", [])

        # Combine all text for checking
        all_text = f"{title} {description} {' '.join(actions)}"

        # Check for "safe" wording in risky verdicts
        if is_risky:
            if _SAFE_WORDING_EN.search(all_text):
                return SafetyFilterResult(
                    passed=False,
                    reason=f"LLM output contains 'safe/genuine/harmless' wording for {verdict} verdict (EN)",
                )
            if _SAFE_WORDING_HI.search(all_text):
                return SafetyFilterResult(
                    passed=False,
                    reason=f"LLM output contains 'safe/genuine/harmless' wording for {verdict} verdict (HI)",
                )

        # Strip HTML/markdown and filter URLs/phones
        title = _strip_formatting(title)
        description = _strip_formatting(description)
        actions = [_filter_urls_phones(_strip_formatting(a)) for a in actions]
        # Remove empty actions
        actions = [a.strip() for a in actions if a.strip()]

        title = _filter_urls_phones(title)
        description = _filter_urls_phones(description)

        if not actions:
            return SafetyFilterResult(
                passed=False,
                reason="All actions were empty after filtering",
            )

        filtered[lang] = {
            "title": title,
            "description": description,
            "actions": actions,
        }

    if not filtered:
        return SafetyFilterResult(
            passed=False,
            reason="No language sections in explanation",
        )

    return SafetyFilterResult(
        passed=True,
        filtered_explanation=filtered,
    )

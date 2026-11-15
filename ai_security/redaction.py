"""PII redaction engine for Indian SMS/WhatsApp/URL content.

Masks sensitive personal information (phone numbers, Aadhaar, cards, OTPs,
PAN, UPI IDs, emails, IFSC, bank accounts) while preserving scam-indicator
keywords that the rule engine needs.

Design principles:
- Single-pass overlap resolution by priority
- Idempotent (re-redacting produces the same output)
- Handles Devanagari digits (०-९) mapped to ASCII before pattern matching
- Never false-positives on amounts (Rs 4,999), years, dates, short refs
- Findings report type and count only, never raw values
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs


# ---------------------------------------------------------------------------
# Devanagari digit mapping
# ---------------------------------------------------------------------------
_DEVANAGARI_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")


def _normalize_devanagari(text: str) -> Tuple[str, bool]:
    """Replace Devanagari digits with ASCII equivalents.

    Returns (normalized_text, had_devanagari).
    """
    normalized = text.translate(_DEVANAGARI_DIGITS)
    return normalized, normalized != text


# ---------------------------------------------------------------------------
# Luhn check for card numbers
# ---------------------------------------------------------------------------
def _luhn_check(digits: str) -> bool:
    """Validate a digit string using the Luhn algorithm."""
    if not digits.isdigit() or len(digits) < 13:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Priority constants (higher = redacted first in overlap resolution)
# ---------------------------------------------------------------------------
_PRIORITY_OTP = 100
_PRIORITY_CARD = 95
_PRIORITY_ACCOUNT = 90
_PRIORITY_AADHAAR = 85
_PRIORITY_PAN = 80
_PRIORITY_IFSC = 75
_PRIORITY_UPI = 70
_PRIORITY_PHONE = 65
_PRIORITY_EMAIL = 55


# ---------------------------------------------------------------------------
# Patterns — each returns (regex, placeholder, priority, validator_fn | None)
# ---------------------------------------------------------------------------

def _build_patterns() -> List[Tuple[re.Pattern, str, int, object]]:
    """Build compiled regex patterns with priorities."""
    patterns = []

    # OTP / PIN / CVV — contextual: digits near keyword
    # Match keyword + optional filler words + separator + digits
    patterns.append((
        re.compile(
            r"(?i)\b(otp|one[- ]?time[- ]?(?:password|code)|pin|mpin|cvv|passcode|verification\s*code|security\s*code)\b"
            r"(?:\s+(?:is|was|will\s*be|है))?"
            r"[\s:.\-–—=]{0,5}"
            r"(\d{3,8})\b"
        ),
        "[OTP_REDACTED]",
        _PRIORITY_OTP,
        None,
    ))

    # Credit/debit card numbers: 13-19 digits, Luhn-checked
    # With separators (space, hyphen) or contiguous
    patterns.append((
        re.compile(
            r"\b(\d[ \-]?){12,18}\d\b"
        ),
        "[CARD_REDACTED]",
        _PRIORITY_CARD,
        lambda m: _luhn_check(re.sub(r"[\s\-]", "", m.group(0))) and len(re.sub(r"[\s\-]", "", m.group(0))) >= 13,
    ))

    # Bank account number: 9-18 digits near context keyword (higher priority than Aadhaar)
    patterns.append((
        re.compile(
            r"(?i)(?:a/?c|account|acct|bank\s*a/?c)[\s:.\-#]{0,5}(\d[\d\s\-]{7,17}\d)\b"
        ),
        "[ACCOUNT_REDACTED]",
        _PRIORITY_ACCOUNT,
        lambda m: 9 <= len(re.sub(r"[\s\-]", "", m.group(1))) <= 18,
    ))

    # Aadhaar: 12 digits, optionally grouped as 4-4-4
    patterns.append((
        re.compile(
            r"\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b"
        ),
        "[AADHAAR_REDACTED]",
        _PRIORITY_AADHAAR,
        lambda m: (
            len(re.sub(r"[\s\-]", "", m.group(0))) == 12
            and not _luhn_check(re.sub(r"[\s\-]", "", m.group(0)))
            # Exclude if it looks like a card (Luhn passes) or amount
            and not re.match(r"(?i)rs\.?\s*$", m.string[max(0, m.start()-5):m.start()])
        ),
    ))

    # PAN: AAAAA0000A pattern
    patterns.append((
        re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        "[PAN_REDACTED]",
        _PRIORITY_PAN,
        None,
    ))

    # IFSC: 4 letters + 0 + 6 alphanumeric
    patterns.append((
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        "[IFSC_REDACTED]",
        _PRIORITY_IFSC,
        None,
    ))

    # UPI ID: xxx@bankname (higher priority than phone)
    patterns.append((
        re.compile(
            r"\b[a-zA-Z0-9._\-]+@(?:upi|paytm|okicici|okhdfcbank|oksbi|okaxis|ybl|ibl|apl|axl|"
            r"axisbank|icici|sbi|hdfcbank|kotak|indus|federal|barodampay|"
            r"jupiteraxis|freecharge|phonepe|gpay|slice|fi|postbank|aubank)\b",
            re.IGNORECASE,
        ),
        "[UPI_REDACTED]",
        _PRIORITY_UPI,
        None,
    ))

    # Indian phone numbers
    # +91 / 0091 / 91 / 0 prefix, starting 6-9, 10 digits with flexible separators
    patterns.append((
        re.compile(
            r"(?:(?:\+91|\b0091|\b91|\b0)[\s\-.]*|\b)"
            r"([6-9](?:[\s\-.]?\d){9})\b"
        ),
        "[PHONE_REDACTED]",
        _PRIORITY_PHONE,
        lambda m: 10 <= len(re.sub(r"\D", "", m.group(0))) <= 14,
    ))

    # Email addresses
    patterns.append((
        re.compile(
            r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
        ),
        "[EMAIL_REDACTED]",
        _PRIORITY_EMAIL,
        None,
    ))

    return patterns


_PATTERNS = _build_patterns()


# ---------------------------------------------------------------------------
# Amount / year / date exclusion guard
# ---------------------------------------------------------------------------
_AMOUNT_PREFIX = re.compile(
    r"(?i)(?:rs\.?|inr|₹|\$|usd)\s*$"
)
_AMOUNT_SUFFIX = re.compile(
    r"(?i)^\s*(?:/-|rs\.?|inr|rupees)\b"
)
_YEAR_PATTERN = re.compile(r"\b(19|20)\d{2}\b")
_DATE_PATTERN = re.compile(
    r"\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b"
)


def _is_amount_or_date(text: str, start: int, end: int, matched: str) -> bool:
    """Check if a matched region is actually a monetary amount, year, or date."""
    prefix = text[max(0, start - 8):start]
    suffix = text[end:min(len(text), end + 8)]
    if _AMOUNT_PREFIX.search(prefix) or _AMOUNT_SUFFIX.search(suffix):
        return True
    clean = re.sub(r"[\s\-]", "", matched)
    if len(clean) == 4 and _YEAR_PATTERN.match(matched.strip()):
        return True
    if _DATE_PATTERN.match(matched.strip()):
        return True
    return False


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------
@dataclass
class RedactionFinding:
    """A single redaction finding — type and count only, never the raw value."""
    pii_type: str
    count: int


@dataclass
class RedactionResult:
    """Result of PII redaction."""
    redacted_text: str
    findings: List[RedactionFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core redaction functions
# ---------------------------------------------------------------------------

def redact_text(text: str) -> RedactionResult:
    """Redact PII from text while preserving scam-indicator keywords.

    Args:
        text: Raw input text (SMS, WhatsApp message, etc.)

    Returns:
        RedactionResult with redacted_text and findings (type + count only).
    """
    if not text or not isinstance(text, str):
        return RedactionResult(redacted_text=text or "", findings=[])

    # Normalize Devanagari digits for pattern matching
    working_text, _ = _normalize_devanagari(text)

    # Collect all matches with their spans and priorities
    all_matches: List[Tuple[int, int, str, int, str]] = []  # (start, end, placeholder, priority, pii_type)

    for pattern, placeholder, priority, validator in _PATTERNS:
        for m in pattern.finditer(working_text):
            start, end = m.start(), m.end()

            # For OTP pattern, only redact the digit group (group 2)
            if placeholder == "[OTP_REDACTED]" and m.lastindex and m.lastindex >= 2:
                start = m.start(2)
                end = m.end(2)

            # For account pattern, only redact the number (group 1)
            if placeholder == "[ACCOUNT_REDACTED]" and m.lastindex and m.lastindex >= 1:
                start = m.start(1)
                end = m.end(1)

            matched_text = working_text[start:end]

            # Skip amounts, years, dates
            if _is_amount_or_date(working_text, start, end, matched_text):
                continue

            # Run custom validator if present
            if validator and not validator(m):
                continue

            pii_type = placeholder.strip("[]").replace("_REDACTED", "")
            all_matches.append((start, end, placeholder, priority, pii_type))

    # Sort by priority descending, then by position
    all_matches.sort(key=lambda x: (-x[3], x[0]))

    # Overlap resolution: higher priority wins
    used_ranges: List[Tuple[int, int]] = []
    accepted: List[Tuple[int, int, str, str]] = []

    for start, end, placeholder, priority, pii_type in all_matches:
        overlaps = False
        for us, ue in used_ranges:
            if start < ue and end > us:
                overlaps = True
                break
        if not overlaps:
            accepted.append((start, end, placeholder, pii_type))
            used_ranges.append((start, end))

    # Sort by position for replacement (reverse order to preserve offsets)
    accepted.sort(key=lambda x: x[0], reverse=True)

    # Count findings
    finding_counts: Dict[str, int] = {}
    for _, _, placeholder, pii_type in accepted:
        finding_counts[pii_type] = finding_counts.get(pii_type, 0) + 1

    # Apply replacements on original text (offsets match 1:1 with working_text)
    result = text
    for start, end, placeholder, _ in accepted:
        result = result[:start] + placeholder + result[end:]

    findings = [
        RedactionFinding(pii_type=k, count=v)
        for k, v in sorted(finding_counts.items())
    ]

    return RedactionResult(redacted_text=result, findings=findings)


def redact_pii(text: str) -> str:
    """Convenience wrapper matching backend's expected signature.

    Returns only the redacted text string.
    """
    return redact_text(text).redacted_text


def redact_url_for_storage(url: str) -> str:
    """Strip sensitive parts of a URL for safe storage.

    Strips: userinfo (user:pass@), query parameter values, fragment.
    Preserves: scheme, host, port, path, query parameter keys.

    The original URL is NOT pre-redacted for detection — the backend needs
    the raw URL in memory for ML analysis. This function is for storage only.
    """
    if not url or not isinstance(url, str):
        return url or ""

    try:
        parsed = urlparse(url)
    except Exception:
        return "[URL_REDACTED]"

    # Strip userinfo
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    # Strip query values (keep keys)
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        sanitized_params = {k: ["[REDACTED]"] for k in params}
        query_str = urlencode(sanitized_params, doseq=True)
    else:
        query_str = ""

    # Reconstruct without fragment
    from urllib.parse import urlunparse
    clean = urlunparse((
        parsed.scheme,
        netloc,
        parsed.path,
        "",          # params
        query_str,
        "",          # fragment (stripped)
    ))

    return clean

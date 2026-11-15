"""Prompt-injection detection for untrusted user-submitted text.

Detects common injection patterns in English, Hindi, and Hinglish,
after NFKC normalization and zero-width/control-character stripping.

Exposed so the backend can use it as a rule signal.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Any


# ---------------------------------------------------------------------------
# Text normalization
# ---------------------------------------------------------------------------

# Zero-width and invisible Unicode characters to strip
_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f"   # zero-width space, joiners, marks
    r"\u2060\u2061\u2062\u2063\u2064"     # word joiner, invisible operators
    r"\ufeff"                              # BOM / zero-width no-break space
    r"\u00ad"                              # soft hyphen
    r"\u034f"                              # combining grapheme joiner
    r"\u061c"                              # Arabic letter mark
    r"\u115f\u1160"                        # Hangul fillers
    r"\u17b4\u17b5"                        # Khmer vowel inherent
    r"\u180e"                              # Mongolian vowel separator
    r"\uffa0"                              # Halfwidth Hangul filler
    r"]"
)

# Control characters (C0/C1) except \n, \r, \t
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _normalize_text(text: str) -> str:
    """NFKC normalize, strip zero-width chars and control characters."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE_CHARS.sub("", text)
    text = _CONTROL_CHARS.sub("", text)
    return text


# ---------------------------------------------------------------------------
# Injection patterns
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: List[Dict[str, Any]] = [
    # English role hijacking
    {
        "id": "ROLE_HIJACK_EN",
        "pattern": re.compile(
            r"(?i)\b(?:you\s+are\s+(?:now\s+)?(?:a|an|the)|act\s+as|pretend\s+(?:to\s+be|you\s+are)|"
            r"assume\s+(?:the\s+)?role|roleplay\s+as|"
            r"from\s+now\s+on\s+you\s+(?:are|will)|your\s+new\s+(?:role|persona|identity))\b"
        ),
        "description": "Role hijacking attempt",
    },
    # Instruction override
    {
        "id": "INSTRUCTION_OVERRIDE",
        "pattern": re.compile(
            r"(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions?|rules?|guidelines?|prompts?)|"
            r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?)|"
            r"forget\s+(?:all\s+)?(?:previous|your|the)\s+(?:instructions?|rules?|context)|"
            r"override\s+(?:your|all|the)\s+(?:instructions?|rules?|guidelines?)|"
            r"new\s+instructions?\s*:)\b"
        ),
        "description": "Instruction override attempt",
    },
    # System prompt extraction
    {
        "id": "SYSTEM_PROMPT_EXTRACT",
        "pattern": re.compile(
            r"(?i)\b(?:(?:what|show|reveal|print|output|display|repeat|tell\s+me)\s+(?:is\s+)?(?:your|the)\s+"
            r"(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?)|"
            r"system\s*prompt\s*[:=]|"
            r"(?:print|echo|output)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?))\b"
        ),
        "description": "System prompt extraction attempt",
    },
    # Fake JSON / verdict injection
    {
        "id": "FAKE_JSON_VERDICT",
        "pattern": re.compile(
            r'(?i)(?:\{\s*"?\s*(?:verdict|risk_?(?:score|level)|result|status|classification)\s*"?\s*:\s*"?\s*'
            r"(?:safe|legitimate|harmless|genuine|not\s*scam|low\s*risk))",
        ),
        "description": "Fake JSON verdict injection",
    },
    # Hindi instruction override
    {
        "id": "INSTRUCTION_OVERRIDE_HI",
        "pattern": re.compile(
            r"(?:पिछले\s*(?:निर्देश|नियम)|सभी\s*(?:निर्देश|नियम)\s*(?:भूल|अनदेखा|छोड़)|"
            r"अब\s*(?:से\s*)?(?:तुम|आप)\s*(?:हो|बन)|नए\s*निर्देश)"
        ),
        "description": "Hindi instruction override attempt",
    },
    # Hinglish patterns
    {
        "id": "INSTRUCTION_OVERRIDE_HINGLISH",
        "pattern": re.compile(
            r"(?i)\b(?:pichle\s*(?:instructions?|nirdesh)\s*(?:bhool|ignore|chod)|"
            r"(?:ab\s+se|abse)\s*(?:tum|aap)\s*(?:ho|ban)|"
            r"naye?\s*(?:instructions?|nirdesh)\s*(?:follow|mano))\b"
        ),
        "description": "Hinglish instruction override attempt",
    },
    # Delimiter / fence breakout
    {
        "id": "DELIMITER_BREAKOUT",
        "pattern": re.compile(
            r"(?:```(?:\s*(?:json|system|assistant|end))?|</?(?:system|assistant|user|message|instruction|prompt)>|"
            r"\[/?(?:SYSTEM|INST|SYS)\]|"
            r"={3,}\s*(?:END|SYSTEM|INSTRUCTIONS?)\s*={3,}|"
            r"-{3,}\s*(?:END|SYSTEM)\s*-{3,})"
        ),
        "description": "Delimiter/fence breakout attempt",
    },
    # Output manipulation
    {
        "id": "OUTPUT_MANIPULATION",
        "pattern": re.compile(
            r"(?i)\b(?:(?:always|must|should)\s+(?:say|respond|output|reply|answer)\s+"
            r"(?:that\s+)?(?:this\s+is\s+)?(?:safe|legitimate|harmless|not\s+(?:a\s+)?scam)|"
            r"(?:mark|classify|label|declare|report)\s+(?:(?:this|the)\s+message|this|it)\s+"
            r"(?:as\s+)?(?:safe|legitimate|harmless|not\s+(?:a\s+)?scam)|"
            r"this\s+(?:is|message\s+is)\s+(?:completely\s+)?(?:safe|legitimate|harmless)[\s,]+(?:ignore|disregard|override))\b"
        ),
        "description": "Output manipulation attempt",
    },
    # Hindi "safe" declaration
    {
        "id": "SAFE_DECLARATION_HI",
        "pattern": re.compile(
            r"(?:(?:इसे|यह|इस\s*संदेश\s*को)\s*(?:सुरक्षित|safe|harmless|genuine)\s*(?:बताओ|बोलो|कहो|मानो|mark\s*करो))"
        ),
        "description": "Hindi safe declaration attempt",
    },
]


def detect_prompt_injection(text: str) -> Dict[str, Any]:
    """Detect prompt injection attempts in user-submitted text.

    Args:
        text: Raw user input (before redaction).

    Returns:
        Dictionary with:
        - detected (bool): True if any injection pattern matched
        - patterns (list): List of matched pattern IDs with descriptions
    """
    if not text or not isinstance(text, str):
        return {"detected": False, "patterns": []}

    normalized = _normalize_text(text)

    matched_patterns: List[Dict[str, str]] = []

    for entry in _INJECTION_PATTERNS:
        if entry["pattern"].search(normalized):
            matched_patterns.append({
                "id": entry["id"],
                "description": entry["description"],
            })

    return {
        "detected": len(matched_patterns) > 0,
        "patterns": matched_patterns,
    }

"""ai_security — PII Redaction, Prompt Injection Defense & LLM Explainer.

Public API (matches backend/app/services/security_client.py expectations):
- redact_pii(text) -> str                     # backend calls this
- redact_text(text) -> RedactionResult         # richer version
- redact_url_for_storage(url) -> str
- detect_prompt_injection(text) -> dict
- generate_explanation(**kwargs) -> dict        # backend calls this
- llm_status() -> str                          # for GET /api/health
"""

from .redaction import redact_text, redact_pii, redact_url_for_storage, RedactionResult
from .injection import detect_prompt_injection
from .llm_explainer import generate_explanation
from .llm_client import get_status as llm_status

__all__ = [
    "redact_text",
    "redact_pii",
    "redact_url_for_storage",
    "RedactionResult",
    "detect_prompt_injection",
    "generate_explanation",
    "llm_status",
]

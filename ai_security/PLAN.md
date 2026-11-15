# ai_security/ — Build Plan

## 1. File Layout

```
ai_security/
├── __init__.py              # Public API exports
├── redaction.py             # PII redaction engine
├── injection.py             # Prompt-injection detection
├── fallback_templates.py    # Deterministic bilingual explanations
├── schemas.py               # Pydantic models for LLM I/O
├── safety_filter.py         # Post-validation of LLM output
├── llm_client.py            # Provider-agnostic LLM HTTP client
├── llm_explainer.py         # Orchestrator: LLM → validate → filter → fallback
├── demo.py                  # CLI demo (__main__ entry)
├── requirements.txt         # Dependencies
├── .env.example             # Template env vars (no real keys)
├── .gitignore               # Ignore .env, __pycache__, etc.
├── README.md                # Documentation + viva Q&A
├── PLAN.md                  # This file
└── tests/
    ├── __init__.py
    ├── test_redaction.py
    ├── test_injection.py
    ├── test_fallback.py
    ├── test_schemas.py
    ├── test_safety_filter.py
    ├── test_llm_client.py
    ├── test_llm_explainer.py
    ├── test_security_invariants.py
    └── test_secret_scan.py
```

## 2. Public Interface

The backend (`security_client.py`) currently imports:
- `from ai_security import redact_pii` → calls `redact_pii(text) -> str`
- `from ai_security import generate_explanation` → calls with `(verdict, risk_score, rule_flags, url_flags)`

We MUST match those names exactly. Additionally we export:
- `redact_text(text) -> RedactionResult` (richer version with findings)
- `redact_url_for_storage(url) -> str`
- `detect_prompt_injection(text) -> dict`
- `llm_status() -> str`

## 3. Threat Model

| Threat | Mitigation |
|--------|-----------|
| LLM downgrades verdict | Pydantic output schema has NO verdict/risk fields; safety filter rejects "safe" wording for risky verdicts |
| Prompt injection via user message | NFKC + zero-width strip; nonce delimiters; delimiter escape; explicit data-not-instructions; injection detector as rule signal |
| PII leakage to LLM | Redaction runs BEFORE any external call; LLM receives only redacted text truncated to 1000 chars |
| PII in logs/storage | Findings report type+count only; never raw values |
| API key in source | .env.example has blanks; .gitignore ignores .env; secret scan test fails on key-like patterns |
| LLM returns malicious content | HTML/markdown stripped; URLs/phones removed unless allowlisted; length limits enforced |
| LLM unavailable | Fallback templates always work with no network; generate_explanation NEVER raises |

## 4. Test List

1. Redaction: phones (+91, 0091, separators), Aadhaar (grouped/ungrouped), cards (Luhn), OTP/PIN/CVV contextual, PAN, UPI, email, IFSC, bank account, Devanagari digits, amounts not redacted, idempotent, URL redaction
2. Injection: English/Hindi/Hinglish payloads, zero-width obfuscation, delimiter breakout, fake JSON, role hijack
3. Fallback: deterministic output per category+risk, helpline numbers present, Hindi marked needs proofreading
4. Schemas: valid/invalid LLM output, length limits, action count limits
5. Safety filter: rejects "safe" wording for Likely Scam (EN + HI), strips HTML, strips URLs/phones except allowlisted
6. LLM client: timeout, retry, no-retry-on-auth, cache hits, no-API-key graceful
7. LLM explainer: end-to-end mock, fallback on every failure mode, never raises
8. Security invariants: LLM cannot lower risk, no PII reaches LLM, no API key in source
9. Secret scan: grep ai_security/ for key-like strings

## 5. Open Questions

- Backend `security_client.py` imports `redact_pii` (returns `str`). Our richer `redact_text` returns `RedactionResult`. We export both; `redact_pii` wraps `redact_text` and returns `.redacted_text`.
- Backend `generate_explanation` signature: `(verdict, risk_score, rule_flags, url_flags)`. Our full version takes more params. We provide a wrapper matching the backend signature that fills defaults.
- The health endpoint hardcodes `"llm_service": "fallback_ready"`. Recommend Aayush call `llm_status()` instead.

## 6. Discrepancies (Doc vs Repo)

| Document says | Repo has | Decision |
|---|---|---|
| `ml_models/` | `model/` | Follow repo |
| `POST /analyze` | `POST /api/scan` | Follow repo |
| Import `redact_pii` | Not `redact_text` | Export both; `redact_pii` wraps `redact_text` |
| `generate_explanation(verdict, risk_score, rule_flags, url_flags)` | Different from full spec | Match backend signature, add optional params |

"""Pydantic schemas for LLM input/output validation.

The output schema intentionally has NO verdict or risk fields,
so the LLM structurally cannot change the verdict.
"""

from __future__ import annotations

from typing import List, Optional

try:
    from pydantic import BaseModel, Field, field_validator
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    # Minimal shim for environments without pydantic
    class BaseModel:  # type: ignore[no-redef]
        def __init__(self, **kwargs: object) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self) -> dict:
            return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

    def Field(default: object = None, **kw: object) -> object:  # type: ignore[no-redef]
        return default

    def field_validator(*args: object, **kw: object):  # type: ignore[no-redef]
        def decorator(fn: object) -> object:
            return fn
        return decorator


# ---------------------------------------------------------------------------
# LLM Output Schema (NO verdict or risk fields)
# ---------------------------------------------------------------------------

class ActionGuideSchema(BaseModel):
    """Single-language explanation output from the LLM.

    Enforced limits:
    - title: max 100 chars
    - description: max 500 chars
    - actions: 2-5 items
    """
    title: str = Field(description="Short title summarizing the finding, max 100 chars")
    description: str = Field(description="Detailed description, max 500 chars")
    actions: List[str] = Field(description="2-5 actionable safety recommendations")

    if HAS_PYDANTIC:
        @field_validator("title")
        @classmethod
        def title_length(cls, v: str) -> str:
            if len(v) > 100:
                v = v[:97] + "..."
            return v

        @field_validator("description")
        @classmethod
        def description_length(cls, v: str) -> str:
            if len(v) > 500:
                v = v[:497] + "..."
            return v

        @field_validator("actions")
        @classmethod
        def actions_count(cls, v: List[str]) -> List[str]:
            if len(v) < 2:
                raise ValueError("At least 2 actions required")
            if len(v) > 5:
                v = v[:5]
            return v


class LLMExplanationOutput(BaseModel):
    """Complete LLM output: bilingual explanations only.

    Intentionally has NO verdict, risk_score, or risk_level fields.
    The LLM structurally cannot influence the detection outcome.
    """
    en: Optional[ActionGuideSchema] = Field(default=None, description="English explanation")
    hi: Optional[ActionGuideSchema] = Field(default=None, description="Hindi explanation")


# ---------------------------------------------------------------------------
# Internal context passed TO the LLM (not returned to user)
# ---------------------------------------------------------------------------

class LLMInputContext(BaseModel):
    """Signals passed to the LLM for explanation generation.

    Contains only already-computed detection signals and optionally
    the REDACTED message text (truncated to 1000 chars).
    Never contains raw PII.
    """
    verdict: str = Field(description="Safe / Suspicious / Likely Scam")
    risk_score: float = Field(description="0-100 risk score")
    risk_level: str = Field(description="low / medium / high")
    rule_flags: List[dict] = Field(default_factory=list)
    ml_text_prediction: Optional[str] = None
    ml_text_probability: Optional[float] = None
    ml_url_prediction: Optional[str] = None
    ml_url_probability: Optional[float] = None
    ml_url_flags: List[str] = Field(default_factory=list)
    domain: Optional[str] = None
    redacted_text: Optional[str] = Field(
        default=None,
        description="REDACTED message, truncated to 1000 chars"
    )

"""Pydantic schemas for request and response validation according to SPEC.md."""

from __future__ import annotations

from typing import List, Optional, Dict, Any

try:
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

    class BaseModel:  # type: ignore
        """Fallback shim when pydantic is not yet installed."""
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self) -> Dict[str, Any]:
            return self.__dict__

        def dict(self) -> Dict[str, Any]:
            return self.__dict__

    def Field(default=None, default_factory=None, description=""):  # type: ignore
        if default_factory is not None:
            return default_factory()
        return default


class ScanRequest(BaseModel):
    """Input payload for scam scan."""
    text: Optional[str] = Field(
        default=None,
        description="SMS, WhatsApp, or email message body to analyze."
    )
    url: Optional[str] = Field(
        default=None,
        description="Suspicious web link to analyze."
    )
    language_preference: Optional[str] = Field(
        default="both",
        description="Desired explanation language: 'both', 'en', or 'hi'."
    )


class RuleFlag(BaseModel):
    """Individual rule triggered by the rule engine."""
    category: str
    rule: str
    severity: str  # "low", "medium", "high", "critical"
    matched_text: str
    description: Optional[str] = None


class RuleDetections(BaseModel):
    """Aggregated output from the rule engine."""
    triggered: bool
    score_contribution: float
    flags: List[RuleFlag] = Field(default_factory=list)
    highlighted_terms: List[str] = Field(default_factory=list)


class TextMLDetections(BaseModel):
    """Output from the text machine learning model."""
    analyzed: bool
    probability: float
    prediction: str  # "scam", "legitimate", "invalid", "not_analyzed"
    model: str = "text_classifier"
    error: Optional[str] = None


class URLMLDetections(BaseModel):
    """Output from the URL machine learning model."""
    analyzed: bool
    probability: float
    prediction: str  # "phishing", "legitimate", "invalid", "not_analyzed"
    flags: List[str] = Field(default_factory=list)
    domain: Optional[str] = None
    model: str = "url_classifier"
    error: Optional[str] = None


class DetectionsContainer(BaseModel):
    """All detection outputs combined."""
    rules: RuleDetections
    text_ml: TextMLDetections
    url_ml: URLMLDetections


class ActionGuide(BaseModel):
    """Language-specific explanation and actionable guidance."""
    title: str
    description: str
    actions: List[str]


class BilingualExplanation(BaseModel):
    """Explanations in English and Hindi."""
    en: Optional[ActionGuide] = None
    hi: Optional[ActionGuide] = None


class ScanResponse(BaseModel):
    """Complete scan result response returned to frontend."""
    scan_id: str
    timestamp: str
    verdict: str  # "Safe", "Suspicious", "Likely Scam"
    risk_score: float
    risk_level: str  # "low", "medium", "high"
    summary: str
    redacted_text: Optional[str] = None
    url: Optional[str] = None
    detections: DetectionsContainer
    explanation: BilingualExplanation


class HistoryItem(BaseModel):
    """Summary of a past scan record."""
    scan_id: str
    timestamp: str
    redacted_text_snippet: Optional[str] = None
    url: Optional[str] = None
    verdict: str
    risk_score: float
    risk_level: str
    top_category: Optional[str] = None


class HistoryResponse(BaseModel):
    """Paginated list of previous scans."""
    total: int
    limit: int
    offset: int
    items: List[HistoryItem]


class CategoryStat(BaseModel):
    """Aggregated statistic for a threat category."""
    category: str
    count: int


class VerdictBreakdown(BaseModel):
    """Count of scans per verdict."""
    safe: int
    suspicious: int
    likely_scam: int


class StatsResponse(BaseModel):
    """Aggregated dashboard statistics."""
    total_scans: int
    verdict_breakdown: VerdictBreakdown
    top_threat_categories: List[CategoryStat]
    average_risk_score: float


class HealthResponse(BaseModel):
    """System health status."""
    status: str
    components: Dict[str, str]
    version: str

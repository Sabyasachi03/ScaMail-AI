"""Detection Fusion Engine.

Merges heuristic rule scores and ML probabilities into an overall Risk Score (0-100)
and maps it to an explainable verdict: Safe, Suspicious, or Likely Scam.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from ..config import (
    WEIGHT_TEXT_ONLY_TEXT,
    WEIGHT_TEXT_ONLY_RULES,
    WEIGHT_URL_ONLY_URL,
    WEIGHT_URL_ONLY_RULES,
    WEIGHT_DUAL_TEXT,
    WEIGHT_DUAL_URL,
    WEIGHT_DUAL_RULES,
    THRESHOLD_SAFE,
    THRESHOLD_SUSPICIOUS,
    CRITICAL_RULE_MIN_SCORE,
    HIGH_ML_MIN_SCORE,
    HIGH_ML_PROB_THRESHOLD,
)


class FusionCalculator:
    """Combines rule engine flags and machine-learning probabilities into a unified verdict."""

    @staticmethod
    def calculate_score(
        rule_result: Dict[str, Any],
        text_ml_prob: Optional[float] = None,
        url_ml_prob: Optional[float] = None,
        has_text: bool = False,
        has_url: bool = False,
    ) -> Dict[str, Any]:
        """Calculates the composite risk score, risk level, and verdict.

        Args:
            rule_result: Output from RuleEngine.evaluate()
            text_ml_prob: Probability (0.0 - 1.0) of text being a scam, or None
            url_ml_prob: Probability (0.0 - 1.0) of URL being phishing, or None
            has_text: Whether text input was provided
            has_url: Whether URL input was provided

        Returns:
            Dict containing risk_score, risk_level, verdict, and applied_overrides
        """
        raw_rule_score = float(rule_result.get("raw_rule_score", 0.0))
        has_critical_rule = bool(rule_result.get("has_critical", False))

        p_text = float(text_ml_prob) if (text_ml_prob is not None and has_text) else None
        p_url = float(url_ml_prob) if (url_ml_prob is not None and has_url) else None

        overrides = []

        # 1. Base Weighted Score Calculation
        if p_text is not None and p_url is not None:
            # Both Text and URL evaluated
            base_score = (
                (WEIGHT_DUAL_TEXT * p_text) +
                (WEIGHT_DUAL_URL * p_url) +
                (WEIGHT_DUAL_RULES * raw_rule_score)
            ) * 100.0
        elif p_text is not None:
            # Text Only evaluated
            base_score = (
                (WEIGHT_TEXT_ONLY_TEXT * p_text) +
                (WEIGHT_TEXT_ONLY_RULES * raw_rule_score)
            ) * 100.0
        elif p_url is not None:
            # URL Only evaluated
            base_score = (
                (WEIGHT_URL_ONLY_URL * p_url) +
                (WEIGHT_URL_ONLY_RULES * raw_rule_score)
            ) * 100.0
        else:
            # Fallback if ML was unavailable: rely strictly on rules
            base_score = raw_rule_score * 100.0

        final_score = base_score

        # 2. Safety Floor Overrides (Fail-Safe Principles)
        # Override A: Critical rule fired (e.g. OTP, AnyDesk, APK)
        if has_critical_rule and final_score < CRITICAL_RULE_MIN_SCORE:
            final_score = CRITICAL_RULE_MIN_SCORE
            overrides.append("CRITICAL_RULE_FLOOR_APPLIED")

        # Override B: Extremely high ML scam confidence
        if (p_text is not None and p_text >= HIGH_ML_PROB_THRESHOLD) or \
           (p_url is not None and p_url >= HIGH_ML_PROB_THRESHOLD):
            if final_score < HIGH_ML_MIN_SCORE:
                final_score = HIGH_ML_MIN_SCORE
                overrides.append("HIGH_ML_CONFIDENCE_FLOOR_APPLIED")

        # Clamp between 0.0 and 100.0
        final_score = max(0.0, min(100.0, final_score))
        final_score = round(final_score, 1)

        # 3. Verdict and Risk Level Mapping
        if final_score < THRESHOLD_SAFE:
            verdict = "Safe"
            risk_level = "low"
        elif final_score < THRESHOLD_SUSPICIOUS:
            verdict = "Suspicious"
            risk_level = "medium"
        else:
            verdict = "Likely Scam"
            risk_level = "high"

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "verdict": verdict,
            "applied_overrides": overrides,
        }

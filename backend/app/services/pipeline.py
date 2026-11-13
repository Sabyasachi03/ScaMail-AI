"""Core integration pipeline orchestrating Redaction -> Rules -> ML -> Fusion -> Explanations -> DB."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from ..rules.rule_engine import RuleEngine
from ..fusion.score_calculator import FusionCalculator
from .ml_client import MLClient
from .security_client import SecurityClient
from ..db.crud import insert_scan_record


class DetectionPipeline:
    """Central engine connecting all ScaMail AI subsystems."""

    def __init__(
        self,
        rule_engine: Optional[RuleEngine] = None,
        fusion_calculator: Optional[FusionCalculator] = None,
        ml_client: Optional[MLClient] = None,
        security_client: Optional[SecurityClient] = None,
    ):
        self.rule_engine = rule_engine or RuleEngine()
        self.fusion = fusion_calculator or FusionCalculator()
        self.ml_client = ml_client or MLClient()
        self.security = security_client or SecurityClient()

    def process(
        self,
        text: Optional[str] = None,
        url: Optional[str] = None,
        language_preference: str = "both",
    ) -> Dict[str, Any]:
        """Executes the end-to-end detection and integration pipeline."""
        clean_text = text.strip() if (text and isinstance(text, str)) else None
        clean_url = url.strip() if (url and isinstance(url, str)) else None

        if not clean_text and not clean_url:
            raise ValueError("At least one non-empty 'text' or 'url' must be provided.")

        scan_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # ----------------------------------------------------------------------
        # Step 1: PII Redaction (Privacy Protection)
        # ----------------------------------------------------------------------
        redacted_text = self.security.redact(clean_text) if clean_text else None

        # ----------------------------------------------------------------------
        # Step 2: Rule Engine Evaluation
        # ----------------------------------------------------------------------
        rule_res = self.rule_engine.evaluate(text=clean_text, url=clean_url)

        # ----------------------------------------------------------------------
        # Step 3: ML Model Inference
        # ----------------------------------------------------------------------
        text_ml_res = self.ml_client.predict_text(clean_text)
        url_ml_res = self.ml_client.predict_url(clean_url)

        text_prob = text_ml_res.get("probability") if text_ml_res.get("analyzed") else None
        url_prob = url_ml_res.get("probability") if url_ml_res.get("analyzed") else None

        # ----------------------------------------------------------------------
        # Step 4: Detection Fusion & Verdict Calculation
        # ----------------------------------------------------------------------
        fusion_res = self.fusion.calculate_score(
            rule_result=rule_res,
            text_ml_prob=text_prob,
            url_ml_prob=url_prob,
            has_text=bool(clean_text),
            has_url=bool(clean_url),
        )

        verdict = fusion_res["verdict"]
        risk_score = fusion_res["risk_score"]
        risk_level = fusion_res["risk_level"]

        # ----------------------------------------------------------------------
        # Step 5: Bilingual AI Explanations
        # ----------------------------------------------------------------------
        explanation = self.security.generate_explanation(
            verdict=verdict,
            risk_score=risk_score,
            rule_flags=rule_res.get("flags", []),
            url_flags=url_ml_res.get("flags", []),
            has_text=bool(clean_text),
            has_url=bool(clean_url),
        )

        # Filter language if requested
        if language_preference == "en":
            explanation = {"en": explanation.get("en"), "hi": None}
        elif language_preference == "hi":
            explanation = {"en": None, "hi": explanation.get("hi")}

        # Top threat category
        top_category = None
        if rule_res.get("flags"):
            top_category = rule_res["flags"][0].get("category")
        elif url_ml_res.get("prediction") == "phishing":
            top_category = "phishing_url"
        elif text_ml_res.get("prediction") == "scam":
            top_category = "scam_text"

        summary = self._generate_summary(verdict, top_category, rule_res.get("flags", []))

        # ----------------------------------------------------------------------
        # Step 6: SQLite Database Logging
        # ----------------------------------------------------------------------
        try:
            insert_scan_record({
                "id": scan_id,
                "created_at": timestamp,
                "redacted_text": redacted_text,
                "url": clean_url,
                "verdict": verdict,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "summary": summary,
                "top_category": top_category,
                "rule_flags": rule_res.get("flags", []),
                "text_ml_prob": text_prob,
                "url_ml_prob": url_prob,
                "explanation_en": explanation.get("en"),
                "explanation_hi": explanation.get("hi"),
            })
        except Exception:
            # Non-blocking if database logging encounters an issue
            pass

        # ----------------------------------------------------------------------
        # Step 7: Final Structured Response
        # ----------------------------------------------------------------------
        return {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "verdict": verdict,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": summary,
            "redacted_text": redacted_text,
            "url": clean_url,
            "detections": {
                "rules": {
                    "triggered": rule_res.get("triggered", False),
                    "score_contribution": rule_res.get("score_contribution", 0.0),
                    "flags": rule_res.get("flags", []),
                    "highlighted_terms": rule_res.get("highlighted_terms", []),
                },
                "text_ml": text_ml_res,
                "url_ml": url_ml_res,
            },
            "explanation": explanation,
        }

    def _generate_summary(
        self,
        verdict: str,
        top_category: Optional[str],
        flags: list,
    ) -> str:
        """Constructs a one-line summary of findings."""
        if verdict == "Safe":
            return "No suspicious patterns detected; verified safe."
        if verdict == "Suspicious":
            return "Ambiguous indicators detected; proceed with caution."
        
        # Likely Scam summaries
        if any(f.get("category") == "credential_theft" for f in flags):
            return "Critical credential/OTP phishing attempt detected."
        if any(f.get("category") == "malicious_tool" for f in flags):
            return "Remote access software hijacking trap detected."
        if any(f.get("category") == "malicious_payload" for f in flags):
            return "Malicious APK download attempt detected."
        if any(f.get("category") == "impersonation" for f in flags):
            return "Urgent institutional impersonation scam detected."
        if any(f.get("category") == "financial_lure" for f in flags):
            return "Fraudulent prize or lottery lure detected."
        return "Strong scam and phishing indicators identified."

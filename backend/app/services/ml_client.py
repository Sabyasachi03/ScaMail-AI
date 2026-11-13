"""Client wrapper for Sabyasachi's Machine Learning models (model/src).

Provides safe calls with graceful fallback when dependencies or model files
are being configured.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Any, Optional

from ..config import MODEL_DIR


class MLClient:
    """Invokes text and URL machine-learning classifiers from model/."""

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = model_dir or MODEL_DIR
        self._text_predictor = None
        self._url_predictor = None
        self._init_predictors()

    def _init_predictors(self) -> None:
        """Attempt to import predictors from model/src."""
        model_str = str(self.model_dir)
        if model_str not in sys.path:
            sys.path.insert(0, model_str)

        try:
            from src.text_predictor import predict_text
            self._text_predictor = predict_text
        except Exception as e:
            self._text_predictor = None

        try:
            from src.url_predictor import predict_url
            self._url_predictor = predict_url
        except Exception as e:
            self._url_predictor = None

    def predict_text(self, text: Optional[str]) -> Dict[str, Any]:
        """Runs the SMS/Text scam classifier."""
        if not text or not isinstance(text, str) or not text.strip():
            return {
                "analyzed": False,
                "probability": 0.0,
                "prediction": "not_analyzed",
                "model": "text_classifier",
            }

        if self._text_predictor is None:
            self._init_predictors()

        if self._text_predictor is not None:
            try:
                res = self._text_predictor(text)
                if res.get("prediction") == "invalid":
                    return {
                        "analyzed": False,
                        "probability": 0.0,
                        "prediction": "invalid",
                        "model": "text_classifier",
                        "error": res.get("error"),
                    }
                return {
                    "analyzed": True,
                    "probability": float(res.get("prob", 0.0)),
                    "prediction": res.get("prediction", "legitimate"),
                    "model": "text_classifier",
                }
            except Exception as e:
                return {
                    "analyzed": False,
                    "probability": 0.0,
                    "prediction": "error",
                    "model": "text_classifier",
                    "error": str(e),
                }

        # Fallback if scikit-learn / joblib / model file not installed in runtime
        return {
            "analyzed": False,
            "probability": 0.0,
            "prediction": "not_analyzed",
            "model": "text_classifier",
            "error": "ML dependencies or model file not yet loaded in active environment",
        }

    def predict_url(self, url: Optional[str]) -> Dict[str, Any]:
        """Runs the Phishing URL classifier."""
        if not url or not isinstance(url, str) or not url.strip():
            return {
                "analyzed": False,
                "probability": 0.0,
                "prediction": "not_analyzed",
                "flags": [],
                "model": "url_classifier",
            }

        if self._url_predictor is None:
            self._init_predictors()

        if self._url_predictor is not None:
            try:
                res = self._url_predictor(url)
                if res.get("prediction") == "invalid":
                    return {
                        "analyzed": False,
                        "probability": 0.0,
                        "prediction": "invalid",
                        "flags": [],
                        "model": "url_classifier",
                        "error": res.get("error"),
                    }
                return {
                    "analyzed": True,
                    "probability": float(res.get("prob", 0.0)),
                    "prediction": res.get("prediction", "legitimate"),
                    "flags": res.get("flags", []),
                    "model": "url_classifier",
                }
            except Exception as e:
                return {
                    "analyzed": False,
                    "probability": 0.0,
                    "prediction": "error",
                    "flags": [],
                    "model": "url_classifier",
                    "error": str(e),
                }

        # Fallback
        return {
            "analyzed": False,
            "probability": 0.0,
            "prediction": "not_analyzed",
            "flags": [],
            "model": "url_classifier",
            "error": "ML dependencies or model file not yet loaded in active environment",
        }

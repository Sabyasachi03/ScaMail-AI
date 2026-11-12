"""FastAPI-friendly inference for the saved URL phishing pipeline."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import joblib

from .url_features import url_flags

MODEL_PATH = Path(__file__).resolve().parents[1] / "saved_model" / "url_phishing_pipeline.joblib"
_MODEL = None


def _load_model():
    global _MODEL
    if _MODEL is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"URL model not found: {MODEL_PATH}. Run notebook 02 first.")
        _MODEL = joblib.load(MODEL_PATH)
    return _MODEL


def _is_usable_url(value: str) -> bool:
    candidate = value if "://" in value else f"//{value}"
    try:
        host = urlparse(candidate).hostname
        # urllib accepts spaces in a netloc; reject those and require a hostname-like value.
        return bool(host) and not any(char.isspace() for char in host) and ("." in host or host == "localhost")
    except ValueError:
        return False


def predict_url(url):
    """Return phishing probability and offline feature-derived flags for one URL."""
    if not isinstance(url, str) or not url.strip() or not _is_usable_url(url.strip()):
        return {"prob": 0.0, "prediction": "invalid", "flags": [], "error": "url must contain a valid hostname"}
    value = url.strip()
    model = _load_model()
    probability = float(model.predict_proba([value])[0, 1])
    return {"prob": round(probability, 6), "prediction": "phishing" if probability >= 0.5 else "legitimate", "flags": url_flags(value)}

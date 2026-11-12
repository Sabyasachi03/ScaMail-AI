"""FastAPI-friendly inference for the saved text scam pipeline."""

from __future__ import annotations

from pathlib import Path

import joblib

MODEL_PATH = Path(__file__).resolve().parents[1] / "saved_model" / "text_scam_pipeline.joblib"
_MODEL = None


def _load_model():
    global _MODEL
    if _MODEL is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Text model not found: {MODEL_PATH}. Run notebook 01 first.")
        _MODEL = joblib.load(MODEL_PATH)
    return _MODEL


def predict_text(text):
    """Return calibrated scam probability for one non-empty SMS/text message."""
    if not isinstance(text, str) or not text.strip():
        return {"prob": 0.0, "prediction": "invalid", "model": "text_classifier", "error": "text must be a non-empty string"}
    model = _load_model()
    probability = float(model.predict_proba([text.strip()])[0, 1])
    return {"prob": round(probability, 6), "prediction": "scam" if probability >= 0.5 else "legitimate", "model": "text_classifier"}

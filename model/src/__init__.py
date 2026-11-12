"""Inference helpers for ScaMail AI's locally saved ML models."""

from .text_predictor import predict_text
from .url_predictor import predict_url

__all__ = ["predict_text", "predict_url"]

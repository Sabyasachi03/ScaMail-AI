"""Configuration settings for ScaMail AI Backend."""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parents[2]  # Repo root /home/joltjoestar/Projects/ScaMail-AI
BACKEND_DIR = BASE_DIR / "backend"
MODEL_DIR = BASE_DIR / "model"
AI_SECURITY_DIR = BASE_DIR / "ai_security"

# Database Configuration
DATABASE_PATH = os.getenv("SCAMAIL_DB_PATH", str(BACKEND_DIR / "scamail.db"))

# Fusion Formula Weights
WEIGHT_TEXT_ONLY_TEXT = 0.60
WEIGHT_TEXT_ONLY_RULES = 0.40

WEIGHT_URL_ONLY_URL = 0.70
WEIGHT_URL_ONLY_RULES = 0.30

WEIGHT_DUAL_TEXT = 0.35
WEIGHT_DUAL_URL = 0.35
WEIGHT_DUAL_RULES = 0.30

# Risk Thresholds
THRESHOLD_SAFE = 35.0         # 0.0 to < 35.0 -> Safe
THRESHOLD_SUSPICIOUS = 70.0   # 35.0 to < 70.0 -> Suspicious, >= 70.0 -> Likely Scam

# Safety Overrides
CRITICAL_RULE_MIN_SCORE = 75.0
HIGH_ML_MIN_SCORE = 70.0
HIGH_ML_PROB_THRESHOLD = 0.85

# Server Settings
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

"""Heuristic patterns, keyword regexes, and severity categories for scam detection.

Designed specifically for smishing, WhatsApp fraud, and phishing campaigns
commonly observed in Indian and global financial ecosystems.
"""

from __future__ import annotations

import re
from typing import List, Dict, Any

# ==============================================================================
# RULE TAXONOMY & DEFINITIONS
# ==============================================================================

RULES: List[Dict[str, Any]] = [
    # --------------------------------------------------------------------------
    # 1. CRITICAL: SENSITIVE CREDENTIAL / OTP REQUESTS
    # --------------------------------------------------------------------------
    {
        "id": "CREDENTIAL_OTP_REQUEST",
        "category": "credential_theft",
        "severity": "critical",
        "weight": 0.45,
        "description": "Requests one-time password (OTP), PIN, or security code.",
        "patterns": [
            r"\b(?:share|send|enter|provide|verify)\b.*?\b(?:otp|one[- ]time[- ]password|pin|cvv|mpin)\b",
            r"\botp\s*(?:is|will be)?\s*(?:required|needed|to be shared)\b",
            r"\bnever share\b.*?\bexcept\b",  # deceptive "never share unless" patterns
            r"\b(?:share|forward)\b.*?\b6[- ]digit\s*code\b",
        ],
    },
    {
        "id": "BANK_PASSWORD_REQUEST",
        "category": "credential_theft",
        "severity": "critical",
        "weight": 0.45,
        "description": "Demands banking credentials or card details.",
        "patterns": [
            r"\b(?:enter|update|submit)\b.*?\b(?:net\s*banking\s*password|login\s*password|atm\s*pin|card\s*number)\b",
            r"\b(?:16[- ]digit\s*card|cvv\s*number|expiry\s*date)\b",
        ],
    },
    {
        "id": "REMOTE_ACCESS_APP",
        "category": "malicious_tool",
        "severity": "critical",
        "weight": 0.45,
        "description": "Urges installation of screen-sharing or remote desktop software.",
        "patterns": [
            r"\b(?:install|download)\b.*?\b(?:anydesk|teamviewer|quicksupport|rustdesk|alpemix|zoho\s*assist)\b",
            r"\b(?:open|connect\s*via)\b.*?\b(?:anydesk|teamviewer|quicksupport)\b",
        ],
    },
    {
        "id": "MALICIOUS_APK_DOWNLOAD",
        "category": "malicious_payload",
        "severity": "critical",
        "weight": 0.40,
        "description": "Prompts user to install an Android APK file directly.",
        "patterns": [
            r"\b(?:download|install|update)\b.*?\b(?:\.apk|apk\s*file|app\s*from\s*link)\b",
            r"https?://[^\s]+\.apk\b",
        ],
    },

    # --------------------------------------------------------------------------
    # 2. HIGH: URGENCY & THREATS
    # --------------------------------------------------------------------------
    {
        "id": "ACCOUNT_SUSPENSION_THREAT",
        "category": "urgency",
        "severity": "high",
        "weight": 0.35,
        "description": "Threatens immediate account blockage, suspension, or deactivation.",
        "patterns": [
            r"\b(?:account|card|sim|service)\b.*?\b(?:will be|has been|is)?\s*(?:blocked|suspended|deactivated|terminated|frozen|closed)\b",
            r"\b(?:block|freeze|deactivate)\s*your\s*(?:account|services?|debit\s*card)\b",
        ],
    },
    {
        "id": "ELECTRICITY_BILL_THREAT",
        "category": "impersonation",
        "severity": "high",
        "weight": 0.35,
        "description": "Impersonates electricity department threatening power cut tonight.",
        "patterns": [
            r"\b(?:electricity|power)\b.*?\b(?:disconnected|cut off|suspended)\b.*?\b(?:tonight|today|by\s*\d{1,2}|unpaid\s*bill)\b",
            r"\b(?:electricity|power)\s*(?:bill|supply|connection|department|officer)\b.*?\b(?:disconnected|cut off|unpaid|pay\s*immediately)\b",
            r"\belectricity\s*officer\b.*?\b\d{10}\b",
        ],
    },
    {
        "id": "PAN_AADHAAR_KYC_DEADLINE",
        "category": "urgency",
        "severity": "high",
        "weight": 0.30,
        "description": "Coerces user with urgent KYC or PAN/Aadhaar linking requirement.",
        "patterns": [
            r"\b(?:kyc|pan[- ]aadhaar|pan\s*card)\b.*?\b(?:pending|incomplete|expired|mandatory|update\s*immediately)\b",
            r"\bkyc[-_\s]*(?:update|verification|status|link|portal)\b",
            r"\b(?:link|update)\b.*?\b(?:pan|aadhaar)\b.*?\b(?:immediately|urgent|today|within\s*\d+\s*(?:hours|hrs))\b",
        ],
    },
    {
        "id": "TIME_PRESSURE_DEADLINE",
        "category": "urgency",
        "severity": "high",
        "weight": 0.25,
        "description": "Applies severe time pressure to force hasty decision.",
        "patterns": [
            r"\b(?:within\s*(?:24|12|48|2)\s*(?:hours|hrs)|immediately|urgently|strictly|last\s*chance|final\s*reminder)\b",
            r"\baction\s*required\s*immediately\b",
        ],
    },

    # --------------------------------------------------------------------------
    # 3. HIGH: FINANCIAL LURES & PRIZES
    # --------------------------------------------------------------------------
    {
        "id": "LOTTERY_OR_CASH_PRIZE",
        "category": "financial_lure",
        "severity": "high",
        "weight": 0.35,
        "description": "Claims unexpected lottery winnings, prize money, or reward points.",
        "patterns": [
            r"\b(?:won|winner|awarded|selected)\b.*?\b(?:lottery|prize|reward|gift\s*card|bonus|kbc|iphone)\b",
            r"\b(?:congratulations|congrats)\b.*?\b(?:claim|won|prize\s*of|rs\.?\s*[\d,]+|\$|credited)\b",
            r"\bcredit\s*of\s*(?:rs\.?|inr)\s*[\d,]+\s*(?:pending|ready\s*to\s*claim)\b",
        ],
    },
    {
        "id": "UNREALISTIC_EARNING_OFFER",
        "category": "financial_lure",
        "severity": "medium",
        "weight": 0.25,
        "description": "Offers work-from-home, part-time like-and-subscribe, or guaranteed high returns.",
        "patterns": [
            r"\b(?:part[- ]time\s*job|work\s*from\s*home)\b.*?\b(?:earn\s*(?:rs\.?|daily)|daily\s*income|like\s*youtube\s*videos)\b",
            r"\b(?:guaranteed|instant)\s*(?:profit|return|crypto\s*earning)\b",
        ],
    },

    # --------------------------------------------------------------------------
    # 4. MEDIUM: INSTITUTION IMPERSONATION
    # --------------------------------------------------------------------------
    {
        "id": "BANK_IMPERSONATION",
        "category": "impersonation",
        "severity": "medium",
        "weight": 0.20,
        "description": "Impersonates major Indian banks or regulatory bodies.",
        "patterns": [
            r"\b(?:sbi|state\s*bank\s*of\s*india|hdfc|icici|axis\s*bank|pnb|punjab\s*national|canara\s*bank|kotak)\b.*?\b(?:alert|notice|customer|support|service)\b",
            r"\b(?:sbi|hdfc|icici|axis|pnb|kotak)[-_.]*(?:secure|login|portal|update|verify|banking|care)\b",
            r"\b(?:reserve\s*bank\s*of\s*india|rbi\s*guidelines?)\b",
        ],
    },
    {
        "id": "GOVT_AUTHORITY_IMPERSONATION",
        "category": "impersonation",
        "severity": "medium",
        "weight": 0.20,
        "description": "Impersonates tax authorities, police, or courier services.",
        "patterns": [
            r"\b(?:income\s*tax\s*department|tax\s*refund|it\s*department|challan|traffic\s*police)\b",
            r"\b(?:india\s*post|courier\s*package|customs\s*clearance)\b.*?\b(?:stuck|failed\s*delivery|pay\s*fee)\b",
        ],
    },

    # --------------------------------------------------------------------------
    # 5. URL SPECIFIC HEURISTICS
    # --------------------------------------------------------------------------
    {
        "id": "URL_SHORTENER_DETECTED",
        "category": "url_obfuscation",
        "severity": "high",
        "weight": 0.30,
        "description": "Uses link-shortening services commonly concealing malicious redirect targets.",
        "patterns": [
            r"(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|ow\.ly|buff\.ly|rebrand\.ly)/[a-zA-Z0-9_\-]+",
        ],
    },
    {
        "id": "IP_HOST_DETECTED",
        "category": "url_anomaly",
        "severity": "high",
        "weight": 0.35,
        "description": "URL points directly to a raw numeric IP address instead of a domain.",
        "patterns": [
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)",
        ],
    },
    {
        "id": "PHISHING_SUBDOMAIN_OR_KEYWORD",
        "category": "url_anomaly",
        "severity": "high",
        "weight": 0.30,
        "description": "Domain contains deceptive trust keywords (e.g., sbi-login, verify-kyc).",
        "patterns": [
            r"(?:kyc[-_.]update|sbi[-_.]secure|secure[-_.]login|verify[-_.]account|bank[-_.]support|refund[-_.]claim|support[-_.]portal)",
        ],
    },
]

# Quick lookup list of critical keywords to highlight in frontend
HIGHLIGHT_WORDS = [
    "urgent", "urgently", "immediately", "blocked", "suspended", "deactivated",
    "otp", "pin", "cvv", "password", "kyc", "pan", "aadhaar", "lottery",
    "winner", "prize", "refund", "electricity", "disconnection", "apk",
    "anydesk", "teamviewer", "quicksupport", "claim", "penalty", "congratulations"
]

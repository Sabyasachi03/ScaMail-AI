"""Client interface for Aman's AI & Security module (ai_security/).

Provides robust PII redaction and high-quality bilingual (English & Hindi)
explanations with offline template fallbacks.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..config import AI_SECURITY_DIR


class SecurityClient:
    """Handles PII redaction and bilingual explanation generation."""

    def __init__(self, ai_security_dir: Optional[Path] = None):
        self.ai_security_dir = ai_security_dir or AI_SECURITY_DIR
        self._external_redactor = None
        self._external_explainer = None
        self._init_external_security()

    def _init_external_security(self) -> None:
        """Attempt to hook into Aman's ai_security module if available."""
        sec_str = str(self.ai_security_dir)
        if sec_str not in sys.path and self.ai_security_dir.exists():
            sys.path.insert(0, sec_str)

        try:
            from ai_security import redact_pii
            self._external_redactor = redact_pii
        except Exception:
            self._external_redactor = None

        try:
            from ai_security import generate_explanation
            self._external_explainer = generate_explanation
        except Exception:
            self._external_explainer = None

    # ==========================================================================
    # 1. PII REDACTION (Privacy First)
    # ==========================================================================
    def redact(self, text: Optional[str]) -> Optional[str]:
        """Redacts sensitive PII: Phone numbers, OTPs, Aadhaar, Cards."""
        if not text or not isinstance(text, str):
            return text

        if self._external_redactor is not None:
            try:
                return self._external_redactor(text)
            except Exception:
                pass

        redacted = text

        # 16-digit card numbers (spaced, hyphenated, or contiguous)
        redacted = re.sub(
            r"\b(?:\d{4}[ -]?){3}\d{4}\b",
            "[CARD_REDACTED]",
            redacted,
        )

        # 12-digit Aadhaar numbers (with optional spaces)
        redacted = re.sub(
            r"\b\d{4}\s\d{4}\s\d{4}\b",
            "[AADHAAR_REDACTED]",
            redacted,
        )

        # Indian phone numbers (+91, 0, or 10-digit beginning with 6-9)
        redacted = re.sub(
            r"(?:\+91[\-\s]?)?[6-9]\d{9}\b",
            "[PHONE_REDACTED]",
            redacted,
        )

        # 4 to 6 digit OTP / PIN when preceded by context keywords
        redacted = re.sub(
            r"(?i)\b(otp|code|pin|password|cvv)([:\s\-]{1,3})\d{3,8}\b",
            r"\g<1>\g<2>[OTP_REDACTED]",
            redacted,
        )

        return redacted

    # ==========================================================================
    # 2. BILINGUAL EXPLANATIONS (English + Hindi)
    # ==========================================================================
    def generate_explanation(
        self,
        verdict: str,
        risk_score: float,
        rule_flags: List[Dict[str, Any]],
        url_flags: List[str],
        has_text: bool,
        has_url: bool,
    ) -> Dict[str, Any]:
        """Generates clear English and Hindi explanations and actionable safety advice."""
        if self._external_explainer is not None:
            try:
                ext_res = self._external_explainer(
                    verdict=verdict,
                    risk_score=risk_score,
                    rule_flags=rule_flags,
                    url_flags=url_flags,
                )
                if ext_res and "en" in ext_res and "hi" in ext_res:
                    return ext_res
            except Exception:
                pass

        # Built-in contextual fallback templates
        categories = {f.get("category") for f in rule_flags}
        rule_ids = {f.get("rule") for f in rule_flags}

        if verdict == "Likely Scam":
            return self._build_scam_explanation(categories, rule_ids, url_flags)
        elif verdict == "Suspicious":
            return self._build_suspicious_explanation(categories, rule_ids, url_flags)
        else:
            return self._build_safe_explanation(has_text, has_url)

    def _build_scam_explanation(
        self,
        categories: set,
        rule_ids: set,
        url_flags: List[str],
    ) -> Dict[str, Any]:
        """Template for Likely Scam verdict."""
        reasons_en = []
        reasons_hi = []
        actions_en = [
            "Do not click on any link or open attached files.",
            "Never share OTP, PIN, NetBanking passwords, or CVV under any circumstances.",
        ]
        actions_hi = [
            "संदेश में दिए गए किसी भी लिंक पर क्लिक न करें और कोई फ़ाइल न खोलें।",
            "किसी भी परिस्थिति में अपना ओटीपी, पिन, नेट-बैंकिंग पासवर्ड या सीवीवी साझा न करें।",
        ]

        if "credential_theft" in categories or "CREDENTIAL_OTP_REQUEST" in rule_ids:
            reasons_en.append("demands confidential credentials or OTPs that legitimate banks never request")
            reasons_hi.append("गोपनीय ओटीपी या पासवर्ड मांग रहा है, जो वैध बैंक कभी नहीं मांगते")

        if "malicious_tool" in categories or "REMOTE_ACCESS_APP" in rule_ids:
            reasons_en.append("instructs you to install remote-desktop software (AnyDesk/TeamViewer) to hijack your device")
            reasons_hi.append("रिमोट एक्सेस ऐप (AnyDesk/TeamViewer) डाउनलोड करने का दबाव बना रहा है")
            actions_en.append("Do not download AnyDesk or TeamViewer on the advice of an unknown sender.")
            actions_hi.append("अज्ञात व्यक्ति के कहने पर AnyDesk या TeamViewer जैसे ऐप बिल्कुल इंस्टॉल न करें।")

        if "malicious_payload" in categories or "MALICIOUS_APK_DOWNLOAD" in rule_ids:
            reasons_en.append("prompts downloading an APK file directly, which can spy on banking applications")
            reasons_hi.append("अनाधिकृत एपीके (APK) फ़ाइल डाउनलोड करने को कह रहा है जो मैलवेयर हो सकती है")

        if "impersonation" in categories or "BANK_IMPERSONATION" in rule_ids:
            reasons_en.append("impersonates a trusted bank or government organization")
            reasons_hi.append("किसी प्रतिष्ठित बैंक या सरकारी विभाग के नाम का दुरुपयोग कर रहा है")
            actions_en.append("Verify directly through official mobile banking apps or your physical bank branch.")
            actions_hi.append("सीधे बैंक की आधिकारिक शाखा या ऐप के माध्यम से पुष्टि करें।")

        if "urgency" in categories or "ACCOUNT_SUSPENSION_THREAT" in rule_ids:
            reasons_en.append("uses manufactured urgency and threats of account closure to pressure you")
            reasons_hi.append("खाता बंद होने का डर दिखाकर जल्दबाजी में निर्णय लेने का दबाव बना रहा है")

        if "financial_lure" in categories:
            reasons_en.append("offers fake lottery prizes or unrealistic earnings to lure you into paying processing fees")
            reasons_hi.append("फर्जी लॉटरी या इनाम का लालच देकर पैसे ऐंठने की कोशिश की जा रही है")

        if not reasons_en:
            reasons_en.append("matches multiple statistical and structural scam indicators")
            reasons_hi.append("धोखाधड़ी और फ़िशिंग के कई पुख्ता संकेत दिखाता है")

        actions_en.append("Report cyber fraud to the national helpline at 1930 or visit cybercrime.gov.in.")
        actions_hi.append("साइबर हेल्पलाइन 1930 पर कॉल करें या cybercrime.gov.in पर रिपोर्ट दर्ज करें।")

        desc_en = f"This input is highly likely to be a scam because it {'; and '.join(reasons_en)}."
        desc_hi = f"यह इनपुट धोखाधड़ी होने की प्रबल संभावना है क्योंकि यह {'; और '.join(reasons_hi)}।"

        return {
            "en": {
                "title": "High Risk: Fraud / Phishing Attempt Detected",
                "description": desc_en,
                "actions": actions_en,
            },
            "hi": {
                "title": "उच्च जोखिम: धोखाधड़ी (स्कैम) का प्रयास पाया गया",
                "description": desc_hi,
                "actions": actions_hi,
            },
        }

    def _build_suspicious_explanation(
        self,
        categories: set,
        rule_ids: set,
        url_flags: List[str],
    ) -> Dict[str, Any]:
        """Template for Suspicious verdict."""
        return {
            "en": {
                "title": "Medium Risk: Suspicious Characteristics Detected",
                "description": "This message or link contains ambiguous or potentially misleading cues such as shortened URLs or generic urgency.",
                "actions": [
                    "Proceed with caution and do not enter personal information on unfamiliar pages.",
                    "Inspect the URL carefully to ensure the domain matches the official entity.",
                    "When in doubt, contact the service provider through official support numbers.",
                ],
            },
            "hi": {
                "title": "मध्यम जोखिम: संदिग्ध संकेत पाए गए",
                "description": "इस संदेश या लिंक में कुछ संदिग्ध लक्षण हैं, जैसे छोटा किया गया लिंक या सामान्य तात्कालिकता।",
                "actions": [
                    "सावधानी बरतें और अपरिचित पेजों पर व्यक्तिगत जानकारी दर्ज न करें।",
                    "वेबसाइट लिंक के डोमेन को ध्यान से जांचें कि क्या वह आधिकारिक है।",
                    "संदेह होने पर संबंधित संस्था से उनके आधिकारिक नंबर पर ही संपर्क करें।",
                ],
            },
        }

    def _build_safe_explanation(self, has_text: bool, has_url: bool) -> Dict[str, Any]:
        """Template for Safe verdict."""
        return {
            "en": {
                "title": "Low Risk: No Obvious Scam Indicators",
                "description": "No prominent phishing heuristics or malicious patterns were identified in this input.",
                "actions": [
                    "While this input appears standard, always remain alert when sharing financial details.",
                    "Ensure any webpage you log into uses HTTPS and a verified domain.",
                ],
            },
            "hi": {
                "title": "कम जोखिम: कोई स्पष्ट धोखाधड़ी संकेत नहीं",
                "description": "इस इनपुट में कोई बड़ा फ़िशिंग या मैलवेयर पैटर्न नहीं पाया गया।",
                "actions": [
                    "हालांकि यह सुरक्षित प्रतीत होता है, वित्तीय लेनदेन करते समय हमेशा सतर्क रहें।",
                    "सुनिश्चित करें कि लॉगिन पेज पर HTTPS और आधिकारिक डोमेन मौजूद हो।",
                ],
            },
        }

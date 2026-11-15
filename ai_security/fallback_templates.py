"""Deterministic bilingual (EN/HI) fallback explanation templates.

Works with no API key and no network. Keyed by dominant threat category
and risk level. Includes helpline guidance (1930, cybercrime.gov.in,
Chakshu on Sanchar Saathi).

NOTE: Hindi text is machine-translated and NEEDS HUMAN PROOF-READING
before final deployment.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpline constants
# ---------------------------------------------------------------------------
_HELPLINE_EN = "Report cyber fraud to the national helpline 1930 or file a complaint at cybercrime.gov.in. To report suspicious calls/SMS, use Chakshu on sancharsaathi.gov.in."
_HELPLINE_HI = "साइबर धोखाधड़ी की शिकायत के लिए राष्ट्रीय हेल्पलाइन 1930 पर कॉल करें या cybercrime.gov.in पर शिकायत दर्ज करें। संदिग्ध कॉल/एसएमएस रिपोर्ट करने के लिए sancharsaathi.gov.in पर चक्षु सुविधा का उपयोग करें।"  # NEEDS HUMAN PROOF-READING


# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------

_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # ======================================================================
    # BANK KYC / IMPERSONATION
    # ======================================================================
    "bank_kyc": {
        "en": {
            "title": "High Risk: Bank KYC / Impersonation Scam",
            "description": (
                "This message impersonates a bank or financial institution and uses "
                "a fake KYC update or account verification deadline to steal your "
                "personal and banking credentials."
            ),
            "actions": [
                "Do not click any link in this message.",
                "Banks never send KYC update links via SMS or WhatsApp.",
                "Verify directly through your bank's official app or branch.",
                _HELPLINE_EN,
            ],
        },
        "hi": {
            "title": "उच्च जोखिम: बैंक KYC / प्रतिरूपण धोखाधड़ी",  # NEEDS HUMAN PROOF-READING
            "description": (
                "यह संदेश किसी बैंक या वित्तीय संस्था का रूप धारण करके नकली KYC अपडेट या "
                "खाता सत्यापन की समयसीमा का डर दिखाकर आपकी बैंकिंग जानकारी चुराने का प्रयास कर रहा है।"
            ),  # NEEDS HUMAN PROOF-READING
            "actions": [
                "इस संदेश में दिए गए किसी भी लिंक पर क्लिक न करें।",
                "बैंक कभी भी SMS या WhatsApp से KYC अपडेट लिंक नहीं भेजते।",
                "सीधे अपने बैंक की आधिकारिक ऐप या शाखा से पुष्टि करें।",
                _HELPLINE_HI,
            ],  # NEEDS HUMAN PROOF-READING
        },
    },

    # ======================================================================
    # OTP / CREDENTIAL REQUEST
    # ======================================================================
    "otp_credential": {
        "en": {
            "title": "High Risk: OTP / Credential Theft Attempt",
            "description": (
                "This message requests sensitive credentials such as OTP, PIN, CVV, "
                "or banking passwords. Legitimate banks and services never ask for "
                "these via SMS, call, or WhatsApp."
            ),
            "actions": [
                "Never share your OTP, PIN, CVV, or net-banking password with anyone.",
                "If you have already shared, change your password immediately and call your bank.",
                "Block the sender's number.",
                _HELPLINE_EN,
            ],
        },
        "hi": {
            "title": "उच्च जोखिम: OTP / गोपनीय जानकारी चोरी का प्रयास",  # NEEDS HUMAN PROOF-READING
            "description": (
                "यह संदेश OTP, PIN, CVV, या बैंकिंग पासवर्ड जैसी गोपनीय जानकारी मांग रहा है। "
                "कोई भी वैध बैंक या सेवा SMS, कॉल या WhatsApp से ऐसी जानकारी नहीं मांगती।"
            ),  # NEEDS HUMAN PROOF-READING
            "actions": [
                "अपना OTP, PIN, CVV या नेट-बैंकिंग पासवर्ड किसी से साझा न करें।",
                "यदि पहले ही साझा कर चुके हैं तो तुरंत पासवर्ड बदलें और बैंक को कॉल करें।",
                "भेजने वाले का नंबर ब्लॉक करें।",
                _HELPLINE_HI,
            ],  # NEEDS HUMAN PROOF-READING
        },
    },

    # ======================================================================
    # LOTTERY / PRIZE SCAM
    # ======================================================================
    "lottery_prize": {
        "en": {
            "title": "High Risk: Fake Lottery / Prize Scam",
            "description": (
                "This message falsely claims you have won a lottery, prize, or reward "
                "and attempts to collect processing fees, tax payments, or personal "
                "information from you."
            ),
            "actions": [
                "You cannot win a lottery you never entered.",
                "Do not pay any 'processing fee', 'tax', or 'registration charge'.",
                "Do not share personal or banking details.",
                _HELPLINE_EN,
            ],
        },
        "hi": {
            "title": "उच्च जोखिम: नकली लॉटरी / इनाम धोखाधड़ी",  # NEEDS HUMAN PROOF-READING
            "description": (
                "यह संदेश झूठा दावा करता है कि आपने लॉटरी, इनाम या पुरस्कार जीता है और "
                "प्रोसेसिंग फीस, टैक्स या व्यक्तिगत जानकारी लेने का प्रयास कर रहा है।"
            ),  # NEEDS HUMAN PROOF-READING
            "actions": [
                "जिस लॉटरी में भाग नहीं लिया, उसमें जीत संभव नहीं है।",
                "कोई 'प्रोसेसिंग फीस', 'टैक्स' या 'रजिस्ट्रेशन चार्ज' न दें।",
                "व्यक्तिगत या बैंकिंग जानकारी साझा न करें।",
                _HELPLINE_HI,
            ],  # NEEDS HUMAN PROOF-READING
        },
    },

    # ======================================================================
    # APK / REMOTE ACCESS APP
    # ======================================================================
    "apk_remote_access": {
        "en": {
            "title": "High Risk: Malicious App / Remote Access Trap",
            "description": (
                "This message instructs you to install an APK file or a remote-access "
                "tool like AnyDesk or TeamViewer. Scammers use these to take full "
                "control of your device and access your banking apps."
            ),
            "actions": [
                "Do not download APK files from unknown links.",
                "Do not install AnyDesk, TeamViewer, or QuickSupport on anyone's instruction via call or SMS.",
                "If already installed, uninstall immediately and scan your device.",
                _HELPLINE_EN,
            ],
        },
        "hi": {
            "title": "उच्च जोखिम: हानिकारक ऐप / रिमोट एक्सेस जाल",  # NEEDS HUMAN PROOF-READING
            "description": (
                "यह संदेश APK फ़ाइल या AnyDesk/TeamViewer जैसे रिमोट-एक्सेस टूल इंस्टॉल "
                "करने को कह रहा है। जालसाज़ इनसे आपके फ़ोन पर पूरा नियंत्रण लेकर बैंकिंग ऐप्स से पैसे चुरा लेते हैं।"
            ),  # NEEDS HUMAN PROOF-READING
            "actions": [
                "अज्ञात लिंक से APK फ़ाइल डाउनलोड न करें।",
                "किसी कॉल या SMS पर AnyDesk, TeamViewer या QuickSupport इंस्टॉल न करें।",
                "यदि पहले ही इंस्टॉल कर चुके हैं तो तुरंत हटाएं और डिवाइस स्कैन करें।",
                _HELPLINE_HI,
            ],  # NEEDS HUMAN PROOF-READING
        },
    },

    # ======================================================================
    # PHISHING URL
    # ======================================================================
    "phishing_url": {
        "en": {
            "title": "High Risk: Phishing Website Detected",
            "description": (
                "The URL in this message appears to be a phishing website designed to "
                "mimic a legitimate service and steal your login credentials or "
                "financial information."
            ),
            "actions": [
                "Do not open or visit the link.",
                "Check the domain carefully — phishing sites use misspelled or lookalike domains.",
                "Access your bank or service only through their official app or by typing the URL yourself.",
                _HELPLINE_EN,
            ],
        },
        "hi": {
            "title": "उच्च जोखिम: फ़िशिंग वेबसाइट का पता चला",  # NEEDS HUMAN PROOF-READING
            "description": (
                "इस संदेश का URL एक फ़िशिंग वेबसाइट प्रतीत होता है जो किसी वैध सेवा की "
                "नकल करके आपकी लॉगिन या वित्तीय जानकारी चुराने के लिए बनाई गई है।"
            ),  # NEEDS HUMAN PROOF-READING
            "actions": [
                "इस लिंक को न खोलें और न ही विज़िट करें।",
                "डोमेन को ध्यान से जांचें — फ़िशिंग साइटें गलत वर्तनी या मिलते-जुलते डोमेन का उपयोग करती हैं।",
                "बैंक या सेवा को केवल उनकी आधिकारिक ऐप से या स्वयं URL टाइप करके एक्सेस करें।",
                _HELPLINE_HI,
            ],  # NEEDS HUMAN PROOF-READING
        },
    },

    # ======================================================================
    # GENERIC HIGH RISK
    # ======================================================================
    "generic_scam": {
        "en": {
            "title": "High Risk: Probable Scam Detected",
            "description": (
                "This input matches multiple statistical and structural indicators "
                "commonly associated with scam or phishing messages."
            ),
            "actions": [
                "Do not respond to this message or click any embedded links.",
                "Do not share any personal, financial, or credential information.",
                "Block the sender and delete the message.",
                _HELPLINE_EN,
            ],
        },
        "hi": {
            "title": "उच्च जोखिम: संभावित धोखाधड़ी का पता चला",  # NEEDS HUMAN PROOF-READING
            "description": (
                "यह इनपुट कई सांख्यिकीय और संरचनात्मक संकेतकों से मेल खाता है जो "
                "आमतौर पर धोखाधड़ी या फ़िशिंग संदेशों से जुड़े होते हैं।"
            ),  # NEEDS HUMAN PROOF-READING
            "actions": [
                "इस संदेश का उत्तर न दें और किसी भी लिंक पर क्लिक न करें।",
                "कोई भी व्यक्तिगत, वित्तीय या गोपनीय जानकारी साझा न करें।",
                "भेजने वाले को ब्लॉक करें और संदेश हटाएं।",
                _HELPLINE_HI,
            ],  # NEEDS HUMAN PROOF-READING
        },
    },
}

# ---------------------------------------------------------------------------
# Suspicious-level templates
# ---------------------------------------------------------------------------

_SUSPICIOUS_TEMPLATE = {
    "en": {
        "title": "Medium Risk: Suspicious Characteristics Detected",
        "description": (
            "This message or link contains ambiguous or potentially misleading "
            "cues such as shortened URLs, generic urgency, or partial pattern matches. "
            "Exercise caution."
        ),
        "actions": [
            "Proceed with caution and do not enter personal information on unfamiliar pages.",
            "Inspect the URL carefully to ensure the domain matches the official entity.",
            "When in doubt, contact the service provider through official support numbers.",
            _HELPLINE_EN,
        ],
    },
    "hi": {
        "title": "मध्यम जोखिम: संदिग्ध लक्षण पाए गए",  # NEEDS HUMAN PROOF-READING
        "description": (
            "इस संदेश या लिंक में कुछ संदिग्ध संकेत हैं जैसे छोटा किया गया लिंक, "
            "सामान्य तात्कालिकता, या आंशिक पैटर्न मिलान। सावधानी बरतें।"
        ),  # NEEDS HUMAN PROOF-READING
        "actions": [
            "सावधानी बरतें और अपरिचित पेजों पर व्यक्तिगत जानकारी दर्ज न करें।",
            "वेबसाइट लिंक के डोमेन को ध्यान से जांचें कि क्या वह आधिकारिक है।",
            "संदेह होने पर संबंधित संस्था से उनके आधिकारिक नंबर पर ही संपर्क करें।",
            _HELPLINE_HI,
        ],  # NEEDS HUMAN PROOF-READING
    },
}

# ---------------------------------------------------------------------------
# Safe-level template
# ---------------------------------------------------------------------------

_SAFE_TEMPLATE = {
    "en": {
        "title": "Low Risk: No Obvious Scam Indicators",
        "description": (
            "No prominent phishing heuristics or malicious patterns were identified "
            "in this input. However, automated analysis is not a guarantee of safety."
        ),
        "actions": [
            "While this input appears standard, always remain alert when sharing financial details.",
            "Ensure any webpage you log into uses HTTPS and a verified domain.",
        ],
    },
    "hi": {
        "title": "कम जोखिम: कोई स्पष्ट धोखाधड़ी संकेत नहीं",  # NEEDS HUMAN PROOF-READING
        "description": (
            "इस इनपुट में कोई बड़ा फ़िशिंग या मैलवेयर पैटर्न नहीं पाया गया। "
            "हालांकि, स्वचालित विश्लेषण सुरक्षा की गारंटी नहीं है।"
        ),  # NEEDS HUMAN PROOF-READING
        "actions": [
            "हालांकि यह सुरक्षित प्रतीत होता है, वित्तीय लेनदेन करते समय हमेशा सतर्क रहें।",
            "सुनिश्चित करें कि लॉगिन पेज पर HTTPS और आधिकारिक डोमेन मौजूद हो।",
        ],  # NEEDS HUMAN PROOF-READING
    },
}


# ---------------------------------------------------------------------------
# Category mapping
# ---------------------------------------------------------------------------

def _determine_category(rule_flags: List[Dict[str, Any]], url_flags: List[str]) -> str:
    """Determine the dominant threat category from detection signals."""
    categories = {f.get("category") for f in rule_flags if isinstance(f, dict)}
    rule_ids = {f.get("rule") for f in rule_flags if isinstance(f, dict)}

    # Priority order for template selection
    if "credential_theft" in categories or "CREDENTIAL_OTP_REQUEST" in rule_ids:
        return "otp_credential"
    if "malicious_tool" in categories or "REMOTE_ACCESS_APP" in rule_ids:
        return "apk_remote_access"
    if "malicious_payload" in categories or "MALICIOUS_APK_DOWNLOAD" in rule_ids:
        return "apk_remote_access"
    if "impersonation" in categories or "PAN_AADHAAR_KYC_DEADLINE" in rule_ids:
        return "bank_kyc"
    if "urgency" in categories and ("ACCOUNT_SUSPENSION_THREAT" in rule_ids or "BANK_IMPERSONATION" in rule_ids):
        return "bank_kyc"
    if "financial_lure" in categories:
        return "lottery_prize"
    if "url_anomaly" in categories or "url_obfuscation" in categories:
        return "phishing_url"
    if any(uf in ("suspicious_keywords", "not_https", "ip_host") for uf in url_flags):
        return "phishing_url"

    return "generic_scam"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def get_fallback_explanation(
    *,
    verdict: str,
    risk_score: float,
    rule_flags: Optional[List[Dict[str, Any]]] = None,
    url_flags: Optional[List[str]] = None,
    language_preference: str = "both",
) -> Dict[str, Any]:
    """Generate a deterministic bilingual fallback explanation.

    Args:
        verdict: "Safe", "Suspicious", or "Likely Scam"
        risk_score: 0-100 numeric risk score
        rule_flags: List of rule flag dicts from rule engine
        url_flags: List of URL flag strings from ML model
        language_preference: "both", "en", or "hi"

    Returns:
        Dictionary with "en" and/or "hi" keys, each containing
        {title, description, actions[]}.
    """
    rule_flags = rule_flags or []
    url_flags = url_flags or []

    if verdict == "Safe":
        template = _SAFE_TEMPLATE
    elif verdict == "Suspicious":
        template = _SUSPICIOUS_TEMPLATE
    else:
        # Likely Scam — pick by dominant threat category
        category = _determine_category(rule_flags, url_flags)
        template = _TEMPLATES.get(category, _TEMPLATES["generic_scam"])

    result: Dict[str, Any] = {}
    if language_preference in ("both", "en"):
        result["en"] = dict(template["en"])  # shallow copy
    if language_preference in ("both", "hi"):
        result["hi"] = dict(template["hi"])  # shallow copy

    return result

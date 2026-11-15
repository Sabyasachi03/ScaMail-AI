"""Tests for safety filter."""

import pytest
from ai_security.safety_filter import apply_safety_filter


class TestSafeWordingRejection:
    """Safety filter must reject 'safe' wording for risky verdicts."""

    def test_reject_safe_for_likely_scam_en(self):
        explanation = {
            "en": {
                "title": "Analysis Complete",
                "description": "This appears to be safe and legitimate.",
                "actions": ["No action needed.", "This is fine."],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is False
        assert "safe" in result.reason.lower() or "genuine" in result.reason.lower()

    def test_reject_genuine_for_likely_scam_en(self):
        explanation = {
            "en": {
                "title": "No Concerns",
                "description": "This is genuine and trustworthy.",
                "actions": ["You can safely proceed.", "No issues found."],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is False

    def test_reject_safe_for_suspicious_en(self):
        explanation = {
            "en": {
                "title": "All Clear",
                "description": "This is completely safe.",
                "actions": ["No risk at all.", "Proceed normally."],
            },
        }
        result = apply_safety_filter(explanation, "Suspicious")
        assert result.passed is False

    def test_reject_safe_for_likely_scam_hi(self):
        explanation = {
            "hi": {
                "title": "विश्लेषण",
                "description": "यह पूरी तरह से सुरक्षित है।",
                "actions": ["कोई चिंता नहीं।", "यह ठीक है।"],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is False

    def test_accept_safe_for_safe_verdict(self):
        explanation = {
            "en": {
                "title": "Low Risk",
                "description": "This appears to be safe.",
                "actions": ["No action needed.", "Stay vigilant."],
            },
        }
        result = apply_safety_filter(explanation, "Safe")
        assert result.passed is True


class TestHTMLStripping:
    """HTML and markdown should be stripped."""

    def test_html_tags_stripped(self):
        explanation = {
            "en": {
                "title": "<b>Warning</b>",
                "description": "<p>This is a <em>scam</em></p>",
                "actions": ["<a href='evil.com'>Click here</a>", "Stay safe"],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is True
        assert "<b>" not in result.filtered_explanation["en"]["title"]
        assert "<p>" not in result.filtered_explanation["en"]["description"]

    def test_markdown_stripped(self):
        explanation = {
            "en": {
                "title": "**Warning**",
                "description": "This is a *scam* attempt",
                "actions": ["Do not `click` the link", "Report this"],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is True
        assert "**" not in result.filtered_explanation["en"]["title"]


class TestURLPhoneStripping:
    """URLs and phones should be stripped unless allowlisted."""

    def test_malicious_url_stripped(self):
        explanation = {
            "en": {
                "title": "Scam Detected",
                "description": "Report to police. Visit https://evil-site.com for details.",
                "actions": ["Report to cybercrime.gov.in", "Call 1930"],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is True
        assert "evil-site.com" not in result.filtered_explanation["en"]["description"]

    def test_allowed_url_preserved(self):
        explanation = {
            "en": {
                "title": "Scam Detected",
                "description": "Report at cybercrime.gov.in",
                "actions": ["Visit cybercrime.gov.in", "Call 1930"],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is True
        assert "cybercrime.gov.in" in result.filtered_explanation["en"]["actions"][0]

    def test_allowed_phone_preserved(self):
        explanation = {
            "en": {
                "title": "Scam Detected",
                "description": "Call the helpline.",
                "actions": ["Call 1930 immediately", "Report online"],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is True
        assert "1930" in result.filtered_explanation["en"]["actions"][0]

    def test_unknown_phone_stripped(self):
        explanation = {
            "en": {
                "title": "Scam Detected",
                "description": "Call +91 9876543210 for refund.",
                "actions": ["Do not call this number", "Report to 1930"],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is True
        assert "9876543210" not in result.filtered_explanation["en"]["description"]


class TestEdgeCases:
    """Edge cases for safety filter."""

    def test_empty_explanation(self):
        result = apply_safety_filter({}, "Likely Scam")
        assert result.passed is False

    def test_none_sections(self):
        result = apply_safety_filter({"en": None, "hi": None}, "Likely Scam")
        assert result.passed is False

    def test_valid_explanation_passes(self):
        explanation = {
            "en": {
                "title": "High Risk: Scam Detected",
                "description": "This message is a phishing attempt.",
                "actions": ["Do not respond", "Report to cybercrime.gov.in"],
            },
            "hi": {
                "title": "उच्च जोखिम: धोखाधड़ी का पता चला",
                "description": "यह संदेश एक फ़िशिंग प्रयास है।",
                "actions": ["उत्तर न दें", "cybercrime.gov.in पर रिपोर्ट करें"],
            },
        }
        result = apply_safety_filter(explanation, "Likely Scam")
        assert result.passed is True
        assert result.filtered_explanation is not None

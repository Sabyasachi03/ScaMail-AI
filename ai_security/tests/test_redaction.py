"""Tests for PII redaction engine."""

import pytest
from ai_security.redaction import redact_text, redact_pii, redact_url_for_storage


class TestPhoneRedaction:
    """Indian mobile number redaction."""

    def test_plus91_phone(self):
        result = redact_text("Call +91 9876543210 now")
        assert "[PHONE_REDACTED]" in result.redacted_text
        assert "9876543210" not in result.redacted_text

    def test_0091_phone(self):
        result = redact_text("Call 0091-9876543210 now")
        assert "[PHONE_REDACTED]" in result.redacted_text

    def test_91_prefix_phone(self):
        result = redact_text("Dial 91 7654321098")
        assert "[PHONE_REDACTED]" in result.redacted_text

    def test_bare_phone(self):
        result = redact_text("Call 9876543210 for details")
        assert "[PHONE_REDACTED]" in result.redacted_text

    def test_phone_with_separators(self):
        result = redact_text("Reach us at 98765-43210")
        assert "[PHONE_REDACTED]" in result.redacted_text

    def test_phone_starting_6_7_8(self):
        for prefix in ["6", "7", "8"]:
            result = redact_text(f"Call {prefix}123456789 now")
            assert "[PHONE_REDACTED]" in result.redacted_text

    def test_no_false_positive_on_5_digit(self):
        """5-digit numbers starting with non 6-9 should not be redacted as phones."""
        result = redact_text("Reference 12345")
        assert "[PHONE_REDACTED]" not in result.redacted_text


class TestOTPRedaction:
    """Contextual OTP/PIN/CVV redaction."""

    def test_otp_keyword(self):
        result = redact_text("Your OTP is 834521")
        assert "[OTP_REDACTED]" in result.redacted_text
        assert "834521" not in result.redacted_text
        # Keyword preserved
        assert "OTP" in result.redacted_text

    def test_pin_keyword(self):
        result = redact_text("Enter PIN: 4523")
        assert "[OTP_REDACTED]" in result.redacted_text
        assert "4523" not in result.redacted_text
        assert "PIN" in result.redacted_text

    def test_cvv_keyword(self):
        result = redact_text("Your CVV 789")
        assert "[OTP_REDACTED]" in result.redacted_text
        assert "CVV" in result.redacted_text

    def test_passcode_keyword(self):
        result = redact_text("Enter passcode 5678 to verify")
        assert "[OTP_REDACTED]" in result.redacted_text

    def test_no_otp_without_context(self):
        """Bare digits without OTP keyword should not be OTP-redacted."""
        result = redact_text("Order number 834521")
        assert "[OTP_REDACTED]" not in result.redacted_text


class TestAadhaarRedaction:
    """Aadhaar-like 12-digit number redaction."""

    def test_aadhaar_spaced(self):
        result = redact_text("Aadhaar: 2345 6789 0123")
        assert "[AADHAAR_REDACTED]" in result.redacted_text
        assert "2345" not in result.redacted_text

    def test_aadhaar_hyphenated(self):
        result = redact_text("ID: 2345-6789-0123")
        assert "[AADHAAR_REDACTED]" in result.redacted_text

    def test_aadhaar_contiguous(self):
        result = redact_text("Your Aadhaar 234567890123 details")
        assert "[AADHAAR_REDACTED]" in result.redacted_text


class TestCardRedaction:
    """Credit/debit card number redaction (Luhn-checked)."""

    def test_valid_card_spaced(self):
        # Visa test number
        result = redact_text("Card: 4111 1111 1111 1111")
        assert "[CARD_REDACTED]" in result.redacted_text
        assert "4111" not in result.redacted_text

    def test_valid_card_contiguous(self):
        result = redact_text("Card 4111111111111111")
        assert "[CARD_REDACTED]" in result.redacted_text

    def test_invalid_luhn_not_redacted_as_card(self):
        """Non-Luhn 16 digits should not be marked as card."""
        result = redact_text("Number 1234567890123456")
        # May be redacted as Aadhaar (first 12 digits) but not as card
        assert "[CARD_REDACTED]" not in result.redacted_text


class TestPANRedaction:
    """PAN (Permanent Account Number) redaction."""

    def test_pan(self):
        result = redact_text("PAN: ABCDE1234F")
        assert "[PAN_REDACTED]" in result.redacted_text
        assert "ABCDE1234F" not in result.redacted_text


class TestUPIRedaction:
    """UPI ID redaction."""

    def test_upi_id(self):
        result = redact_text("Pay to user@upi")
        assert "[UPI_REDACTED]" in result.redacted_text

    def test_upi_paytm(self):
        result = redact_text("Send to 9876543210@paytm")
        assert "[UPI_REDACTED]" in result.redacted_text

    def test_upi_ybl(self):
        result = redact_text("UPI: name@ybl")
        assert "[UPI_REDACTED]" in result.redacted_text


class TestEmailRedaction:
    """Email address redaction."""

    def test_email(self):
        result = redact_text("Email us at test@example.com")
        assert "[EMAIL_REDACTED]" in result.redacted_text
        assert "test@example.com" not in result.redacted_text


class TestIFSCRedaction:
    """IFSC code redaction."""

    def test_ifsc(self):
        result = redact_text("IFSC: SBIN0001234")
        assert "[IFSC_REDACTED]" in result.redacted_text


class TestAccountRedaction:
    """Bank account number redaction (contextual)."""

    def test_account_with_context(self):
        result = redact_text("A/C 12345678901234")
        assert "[ACCOUNT_REDACTED]" in result.redacted_text

    def test_account_keyword(self):
        result = redact_text("Account: 987654321012")
        assert "[ACCOUNT_REDACTED]" in result.redacted_text


class TestDevanagariDigits:
    """Devanagari digit handling."""

    def test_devanagari_phone(self):
        result = redact_text("कॉल करें ९८७६५४३२१०")
        assert "[PHONE_REDACTED]" in result.redacted_text

    def test_devanagari_otp(self):
        result = redact_text("OTP है ५६७८")
        assert "[OTP_REDACTED]" in result.redacted_text


class TestAmountDateExclusion:
    """Amounts, years, and dates should NOT be redacted."""

    def test_amount_rs(self):
        result = redact_text("Price is Rs 4,999 only")
        assert "[CARD_REDACTED]" not in result.redacted_text
        assert "[AADHAAR_REDACTED]" not in result.redacted_text

    def test_year(self):
        result = redact_text("Valid till 2025")
        assert "[PHONE_REDACTED]" not in result.redacted_text

    def test_date(self):
        result = redact_text("Date: 15/11/2024")
        assert "[PHONE_REDACTED]" not in result.redacted_text


class TestIdempotent:
    """Re-redacting already-redacted text gives same result."""

    def test_idempotent(self):
        original = "Call +91 9876543210 with OTP 1234"
        first = redact_pii(original)
        second = redact_pii(first)
        assert first == second


class TestKeywordPreservation:
    """Scam keywords must remain intact."""

    def test_keywords_preserved(self):
        text = "Your OTP is 5678. KYC update required urgently."
        result = redact_pii(text)
        assert "OTP" in result
        assert "KYC" in result
        assert "urgently" in result


class TestFindings:
    """Findings report type and count only."""

    def test_findings_format(self):
        result = redact_text("Call 9876543210 OTP is 1234")
        for f in result.findings:
            assert hasattr(f, "pii_type")
            assert hasattr(f, "count")
            assert isinstance(f.count, int)


class TestRedactPii:
    """Test the simple string-returning wrapper."""

    def test_returns_string(self):
        result = redact_pii("Call 9876543210")
        assert isinstance(result, str)
        assert "[PHONE_REDACTED]" in result


class TestURLRedaction:
    """URL redaction for storage."""

    def test_strips_query_values(self):
        result = redact_url_for_storage("https://example.com/path?token=secret123&user=john")
        assert "secret123" not in result
        assert "john" not in result
        assert "token=" in result
        assert "example.com" in result

    def test_strips_userinfo(self):
        result = redact_url_for_storage("https://admin:password@example.com/path")
        assert "admin" not in result
        assert "password" not in result
        assert "example.com" in result

    def test_strips_fragment(self):
        result = redact_url_for_storage("https://example.com/path#section")
        assert "section" not in result

    def test_preserves_path(self):
        result = redact_url_for_storage("https://example.com/api/v1/scan")
        assert "/api/v1/scan" in result

    def test_empty_url(self):
        assert redact_url_for_storage("") == ""
        assert redact_url_for_storage(None) == ""

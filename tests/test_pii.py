"""Unit tests for the PII guard. Deterministic, no model needed.

All test values are documentation-safe examples: example.com domains,
the official IBAN test numbers and the public card-network test numbers.
"""

from gateway import pii
from gateway.config import PiiConfig
from gateway.models import Verdict


def test_email_redacted():
    text = "Contact maria.huber@example.com for details."
    redacted, rules = pii.redact(text)
    assert "maria.huber@example.com" not in redacted
    assert "[EMAIL]" in redacted
    assert "pii.email" in rules


def test_valid_iban_redacted():
    text = "My IBAN is DE89 3704 0044 0532 0130 00 for the refund."
    redacted, rules = pii.redact(text)
    assert "DE89" not in redacted
    assert "[IBAN]" in redacted
    assert "pii.iban" in rules


def test_invalid_iban_not_redacted():
    # Same shape, but the mod-97 checksum fails -> must NOT be redacted.
    text = "Code DE89 3704 0044 0532 0130 01 is an order number."
    redacted, rules = pii.redact(text)
    assert "pii.iban" not in rules
    assert "DE89 3704 0044 0532 0130 01" in redacted


def test_valid_credit_card_redacted():
    text = "Card: 4111 1111 1111 1111, expiry 12/27."
    redacted, rules = pii.redact(text)
    assert "4111" not in redacted
    assert "[CARD]" in redacted
    assert "pii.credit_card" in rules


def test_invalid_credit_card_not_redacted():
    # Fails the Luhn check -> stays untouched.
    text = "Tracking number 4111 1111 1111 1112 was scanned."
    redacted, rules = pii.redact(text)
    assert "pii.credit_card" not in rules


def test_phone_international_redacted():
    text = "Call me at +1 415 555 0132 tomorrow."
    redacted, rules = pii.redact(text)
    assert "0132" not in redacted
    assert "[PHONE]" in redacted


def test_phone_national_redacted():
    text = "Meine Nummer ist 0664 1234567."
    redacted, rules = pii.redact(text)
    assert "[PHONE]" in redacted


def test_short_numbers_not_redacted():
    # Years, prices and small IDs must not look like phone numbers.
    text = "In 2024 we sold 1500 units for 99 euros."
    redacted, rules = pii.redact(text)
    assert rules == []
    assert redacted == text


def test_german_address_redacted():
    text = "Ich wohne in der Hauptstraße 12 in Linz."
    redacted, rules = pii.redact(text)
    assert "Hauptstraße 12" not in redacted
    assert "[ADDRESS]" in redacted


def test_english_address_redacted():
    text = "Deliver it to 42 Baker Street please."
    redacted, rules = pii.redact(text)
    assert "42 Baker Street" not in redacted
    assert "[ADDRESS]" in redacted


def test_multiple_pii_types_in_one_text():
    text = "Mail anna@example.org or call +43 660 1234567."
    redacted, rules = pii.redact(text)
    assert "[EMAIL]" in redacted and "[PHONE]" in redacted
    assert "anna@example.org" not in redacted


def test_disabled_detector_is_skipped():
    cfg = PiiConfig()
    cfg.enabled["email"] = False
    text = "Mail anna@example.org now."
    redacted, rules = pii.redact(text, cfg)
    assert "anna@example.org" in redacted
    assert rules == []


def test_check_returns_redact_verdict():
    result = pii.check("Reach me at test@example.com")
    assert result.verdict == Verdict.REDACT
    assert result.transformed_text is not None
    assert "[EMAIL]" in result.transformed_text


def test_check_returns_pass_for_clean_text():
    result = pii.check("The quarterly report is ready for review.")
    assert result.verdict == Verdict.PASS

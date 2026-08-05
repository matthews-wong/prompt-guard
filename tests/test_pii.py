"""PII/secret detectors: true positives hit, Luhn rejects invalid cards."""

from __future__ import annotations

from promptguard import pii
from promptguard.models import Severity
from promptguard.pii import _luhn_valid


def test_email_detected() -> None:
    findings = pii.detect_emails("contact me at jane.doe@example.com please")
    assert len(findings) == 1
    assert findings[0].matched == "jane.doe@example.com"
    assert findings[0].category == "pii.email"


def test_email_absent_when_none() -> None:
    assert pii.detect_emails("no addresses here, just text") == []


def test_phone_detected() -> None:
    findings = pii.detect_phones("call +1 (415) 555-0132 today")
    assert findings
    assert any("555" in f.matched for f in findings)


def test_short_number_not_phone() -> None:
    # Four digits should not trip the phone detector.
    assert pii.detect_phones("room 2024") == []


def test_valid_visa_card_detected() -> None:
    # 4111 1111 1111 1111 is a well-known Luhn-valid test number.
    findings = pii.detect_credit_cards("card 4111 1111 1111 1111 on file")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_luhn_invalid_card_rejected() -> None:
    # Same shape, last digit changed so Luhn fails.
    assert pii.detect_credit_cards("card 4111 1111 1111 1112 on file") == []


def test_luhn_checksum_function() -> None:
    assert _luhn_valid("4111111111111111") is True
    assert _luhn_valid("4111111111111112") is False
    assert _luhn_valid("79927398713") is True  # canonical Luhn example
    assert _luhn_valid("") is False
    assert _luhn_valid("abc") is False


def test_ipv4_detected() -> None:
    findings = pii.detect_ips("server at 192.168.1.24 is up")
    assert len(findings) == 1
    assert findings[0].matched == "192.168.1.24"


def test_invalid_ip_octet_not_detected() -> None:
    assert pii.detect_ips("value 999.999.1.1 is not an ip") == []


def test_prefixed_secret_detected() -> None:
    findings = pii.detect_secrets("key AKIAIOSFODNN7EXAMPLE deployed")
    assert findings
    assert findings[0].severity == Severity.HIGH
    assert findings[0].matched == "AKIAIOSFODNN7EXAMPLE"


def test_openai_style_key_detected() -> None:
    findings = pii.detect_secrets("token sk-abcdefghijklmnopqrstuvwxyz123456")
    assert any(f.category == "pii.secret" for f in findings)


def test_plain_word_not_secret() -> None:
    assert pii.detect_secrets("this is an ordinary sentence with words") == []


def test_detect_all_combines_categories() -> None:
    text = "email a@b.com card 4111 1111 1111 1111 ip 10.0.0.1"
    categories = {f.category for f in pii.detect_all(text)}
    assert {"pii.email", "pii.credit_card", "pii.ip"} <= categories

"""PII / secret detectors.

Each public ``detect_*`` function takes the raw text and returns a list of
:class:`~promptguard.models.Finding`. Detectors are pure and deterministic:
same input, same findings, no IO, no network.

The credit-card detector additionally validates candidates with the Luhn
checksum so that arbitrary 16-digit numbers are not flagged as cards.
"""

from __future__ import annotations

import re

from promptguard.models import Finding, Severity

# --- Regex patterns ---------------------------------------------------------
# Kept intentionally readable over maximally strict; this is a pre-filter that
# favours recall, and false positives are surfaced as findings for a human/next
# stage to weigh rather than silently dropped.

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
)

# International-ish phone numbers: optional +, groups of digits separated by
# spaces, dashes or dots, 7-15 digits total.
_PHONE_RE = re.compile(
    r"(?<![\w.])(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}(?![\w])",
)

# Candidate card numbers: 13-19 digits, optionally split into groups by spaces
# or dashes. Validated with Luhn before being reported.
_CARD_RE = re.compile(
    r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])",
)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
)

# API-key / secret-like tokens. Two complementary shapes:
#   1. Known prefixes (AWS, OpenAI, GitHub, Slack, Google) followed by a body.
#   2. Generic long high-entropy-looking alphanumeric runs.
_SECRET_PREFIXED_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}"
    r"|sk-[A-Za-z0-9]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_\-]{20,})\b",
)
_SECRET_GENERIC_RE = re.compile(
    r"(?<![\w/+=-])[A-Za-z0-9_\-]{32,}(?![\w/+=-])",
)

# A minimum digit count guards against flagging things that merely look phone-ish.
_MIN_PHONE_DIGITS = 7


def _luhn_valid(digits: str) -> bool:
    """Return True if ``digits`` (a string of only 0-9) passes Luhn."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    # Process from the rightmost digit, doubling every second one.
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def detect_emails(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _EMAIL_RE.finditer(text):
        findings.append(
            Finding(
                category="pii.email",
                severity=Severity.MEDIUM,
                message="Email address detected.",
                start=match.start(),
                end=match.end(),
                matched=match.group(),
            )
        )
    return findings


def detect_phones(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _PHONE_RE.finditer(text):
        raw = match.group()
        digit_count = sum(ch.isdigit() for ch in raw)
        if digit_count < _MIN_PHONE_DIGITS:
            continue
        findings.append(
            Finding(
                category="pii.phone",
                severity=Severity.LOW,
                message="Phone-number-like sequence detected.",
                start=match.start(),
                end=match.end(),
                matched=raw,
            )
        )
    return findings


def detect_credit_cards(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _CARD_RE.finditer(text):
        raw = match.group()
        digits = re.sub(r"[ -]", "", raw)
        if not (13 <= len(digits) <= 19):
            continue
        if not _luhn_valid(digits):
            continue
        findings.append(
            Finding(
                category="pii.credit_card",
                severity=Severity.HIGH,
                message="Credit-card-like number detected (passes Luhn checksum).",
                start=match.start(),
                end=match.end(),
                matched=raw,
            )
        )
    return findings


def detect_ips(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _IPV4_RE.finditer(text):
        findings.append(
            Finding(
                category="pii.ip",
                severity=Severity.LOW,
                message="IPv4 address detected.",
                start=match.start(),
                end=match.end(),
                matched=match.group(),
            )
        )
    return findings


def detect_secrets(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen_spans: set[tuple[int, int]] = set()

    for match in _SECRET_PREFIXED_RE.finditer(text):
        span = (match.start(), match.end())
        seen_spans.add(span)
        findings.append(
            Finding(
                category="pii.secret",
                severity=Severity.HIGH,
                message="API-key / secret-like token detected (known prefix).",
                start=match.start(),
                end=match.end(),
                matched=match.group(),
            )
        )

    for match in _SECRET_GENERIC_RE.finditer(text):
        span = (match.start(), match.end())
        # Skip if already covered by a more specific prefixed match.
        if any(span[0] >= s and span[1] <= e for s, e in seen_spans):
            continue
        token = match.group()
        # Require a mix of letters and digits to look key-like rather than a word.
        if not (any(c.isalpha() for c in token) and any(c.isdigit() for c in token)):
            continue
        findings.append(
            Finding(
                category="pii.secret",
                severity=Severity.MEDIUM,
                message="High-entropy token detected (possible secret / API key).",
                start=match.start(),
                end=match.end(),
                matched=token,
            )
        )
    return findings


def detect_all(text: str) -> list[Finding]:
    """Run every PII/secret detector and return the combined findings."""
    findings: list[Finding] = []
    findings.extend(detect_emails(text))
    findings.extend(detect_phones(text))
    findings.extend(detect_credit_cards(text))
    findings.extend(detect_ips(text))
    findings.extend(detect_secrets(text))
    return findings

"""Detector registry.

Aggregates the injection heuristics (:mod:`promptguard.injection`) and the
PII/secret detectors (:mod:`promptguard.pii`) behind a single entry point so
the scanner does not need to know about individual rule modules.

Each detector is a callable ``(text) -> list[Finding]``; adding a new detector
is a one-line registration here.
"""

from __future__ import annotations

from typing import Callable

from promptguard import pii
from promptguard.injection import detect_injection
from promptguard.models import Finding

Detector = Callable[[str], list[Finding]]

# The ordered set of detectors run for every scan. Injection first, then PII.
DETECTORS: tuple[Detector, ...] = (
    detect_injection,
    pii.detect_emails,
    pii.detect_phones,
    pii.detect_credit_cards,
    pii.detect_ips,
    pii.detect_secrets,
)


def run_all(text: str) -> list[Finding]:
    """Run every registered detector and return findings sorted by position.

    Findings are ordered by ``(start, -severity)`` so earlier spans come first
    and, on a tie, the more severe finding leads.
    """
    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(text))
    findings.sort(key=lambda f: (f.start, -int(f.severity)))
    return findings

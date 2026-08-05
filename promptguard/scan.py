"""Scan orchestration: text in, :class:`RiskReport` out.

This is the library's primary entry point. It runs every registered detector,
computes the overall severity, and attaches a redacted copy of the input.
"""

from __future__ import annotations

from promptguard.detectors import run_all
from promptguard.models import RiskReport
from promptguard.redact import redact


def scan(text: str) -> RiskReport:
    """Screen ``text`` and return a structured :class:`RiskReport`.

    The scan is fully offline and deterministic: identical input always yields
    an identical report.
    """
    findings = run_all(text)
    redacted = redact(text, findings)
    return RiskReport(text=text, findings=findings, redacted=redacted)

"""Core data types shared across detectors, scanning, and redaction.

Kept dependency-free (stdlib only) so the domain model stays independent of
the CLI framework and any IO concerns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered risk levels.

    Modelled as an ``IntEnum`` so findings and reports can be compared and the
    overall severity of a report is simply ``max(...)`` of its findings.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """A single risk detected in the scanned text.

    Attributes:
        category: Machine-readable detector category (e.g. ``"injection.override"``).
        severity: How serious this match is on its own.
        message: Human-readable explanation of why it was flagged.
        start: Start offset of the matched span in the original text.
        end: End offset (exclusive) of the matched span.
        matched: The exact substring that triggered the finding.
    """

    category: str
    severity: Severity
    message: str
    start: int
    end: int
    matched: str

    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity.label,
            "message": self.message,
            "start": self.start,
            "end": self.end,
            "matched": self.matched,
        }


@dataclass
class RiskReport:
    """Aggregated result of scanning one piece of text.

    Findings are ordered by their position in the source text. ``overall`` is
    the maximum severity across all findings (``INFO`` when the text is clean).
    """

    text: str
    findings: list[Finding] = field(default_factory=list)
    redacted: str = ""

    @property
    def overall(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    @property
    def is_clean(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall.label,
            "is_clean": self.is_clean,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "redacted": self.redacted,
        }

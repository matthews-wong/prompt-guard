"""Redaction: produce a copy of the input with sensitive spans masked.

Redaction is span-based and deterministic. Overlapping findings are merged so
each character is masked at most once, and spans are replaced right-to-left so
earlier offsets stay valid while rewriting.
"""

from __future__ import annotations

from promptguard.models import Finding

# Category prefix -> placeholder label shown in the redacted output.
_LABELS: dict[str, str] = {
    "pii.email": "EMAIL",
    "pii.phone": "PHONE",
    "pii.credit_card": "CARD",
    "pii.ip": "IP",
    "pii.secret": "SECRET",
    "injection": "INJECTION",
}


def _label_for(category: str) -> str:
    if category in _LABELS:
        return _LABELS[category]
    # Fall back to the top-level namespace (e.g. "injection.override" -> INJECTION).
    root = category.split(".", 1)[0]
    return _LABELS.get(root, root.upper())


def redact(text: str, findings: list[Finding]) -> str:
    """Return ``text`` with every finding's span replaced by a ``[LABEL]`` tag."""
    if not findings:
        return text

    # Merge overlapping / adjacent spans, keeping the earliest label.
    ordered = sorted(findings, key=lambda f: (f.start, f.end))
    merged: list[tuple[int, int, str]] = []
    for finding in ordered:
        label = _label_for(finding.category)
        if merged and finding.start <= merged[-1][1]:
            prev_start, prev_end, prev_label = merged[-1]
            merged[-1] = (prev_start, max(prev_end, finding.end), prev_label)
        else:
            merged.append((finding.start, finding.end, label))

    # Apply replacements right-to-left to preserve earlier offsets.
    result = text
    for start, end, label in reversed(merged):
        result = f"{result[:start]}[{label}]{result[end:]}"
    return result

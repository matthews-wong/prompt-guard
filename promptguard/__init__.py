"""prompt-guard: an offline, deterministic pre-filter that screens text
going into an LLM for prompt-injection / jailbreak patterns and PII.

This is a heuristic pre-filter, not a security guarantee. It complements —
never replaces — model-side safety controls.
"""

from promptguard.models import Finding, RiskReport, Severity
from promptguard.scan import scan

__all__ = ["Finding", "RiskReport", "Severity", "scan", "__version__"]

__version__ = "0.1.0"

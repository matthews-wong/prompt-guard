"""Prompt-injection / jailbreak heuristics.

A curated set of case-insensitive regex rules for the phrasings most commonly
used to override an assistant's instructions, escape delimiters, escalate
roles, or exfiltrate the system prompt.

These are heuristics: they catch known patterns, not novel attacks. Treat a
clean result as "no known pattern matched", never as "safe".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from promptguard.models import Finding, Severity


@dataclass(frozen=True)
class _Rule:
    category: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]


def _rule(category: str, severity: Severity, message: str, regex: str) -> _Rule:
    return _Rule(category, severity, message, re.compile(regex, re.IGNORECASE))


# Rules are grouped by attack technique. Order is stable; findings are sorted
# by position after collection.
_RULES: tuple[_Rule, ...] = (
    # --- Instruction override ------------------------------------------------
    _rule(
        "injection.override",
        Severity.HIGH,
        "Attempt to ignore or override prior instructions.",
        r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,20}?"
        r"\b(?:instruction|instructions|prompt|prompts|rule|rules|context)\b",
    ),
    _rule(
        "injection.override",
        Severity.HIGH,
        "Attempt to discard the system prompt or reset behaviour.",
        r"\b(?:ignore|disregard|forget)\b[^.\n]{0,30}?\bsystem\b",
    ),
    # --- System-prompt exfiltration -----------------------------------------
    _rule(
        "injection.exfiltration",
        Severity.HIGH,
        "Attempt to reveal or repeat the system prompt / hidden instructions.",
        r"\b(?:reveal|repeat|print|show|display|output|tell me|what (?:is|are|were))\b"
        r"[^.\n]{0,40}?\b(?:system prompt|system message|initial instructions|"
        r"your instructions|hidden (?:prompt|instructions)|the prompt above)\b",
    ),
    # --- Role override / persona injection ----------------------------------
    _rule(
        "injection.role_override",
        Severity.HIGH,
        "Role-override / jailbreak persona attempt.",
        r"\b(?:you are now|act as|pretend to be|from now on you are|"
        r"you are no longer|enable|activate)\b[^.\n]{0,30}?"
        r"\b(?:dan|do anything now|developer mode|jailbreak|unrestricted|"
        r"no restrictions|without restrictions|admin|root|sudo)\b",
    ),
    _rule(
        "injection.role_override",
        Severity.MEDIUM,
        "Instruction to abandon safety rules or content policy.",
        r"\b(?:ignore|bypass|disable|turn off|forget)\b[^.\n]{0,30}?"
        r"\b(?:safety|guardrails?|content policy|filters?|restrictions?|"
        r"moderation|guidelines)\b",
    ),
    # --- Delimiter / injection framing --------------------------------------
    _rule(
        "injection.delimiter",
        Severity.MEDIUM,
        "Fake conversation delimiter / role marker (prompt-injection framing).",
        r"(?:^|\n)\s*(?:###\s*)?(?:system|assistant|user)\s*:",
    ),
    _rule(
        "injection.delimiter",
        Severity.MEDIUM,
        "Chat-template / special token injection.",
        r"(?:<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>|\[/?INST\]|\[/?SYS\])",
    ),
    _rule(
        "injection.delimiter",
        Severity.LOW,
        "'End of prompt' style delimiter escape.",
        r"\b(?:end of (?:prompt|instructions|system)|"
        r"the (?:text|instructions) above (?:are|is) (?:fake|not real))\b",
    ),
)


def detect_injection(text: str) -> list[Finding]:
    """Return all injection/jailbreak findings for ``text``."""
    findings: list[Finding] = []
    for rule in _RULES:
        for match in rule.pattern.finditer(text):
            findings.append(
                Finding(
                    category=rule.category,
                    severity=rule.severity,
                    message=rule.message,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group().strip(),
                )
            )
    return findings

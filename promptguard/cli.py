"""Command-line interface for prompt-guard.

Reads text from a file or stdin, scans it, and prints either a human-readable
risk report or machine-readable JSON. Exit code is non-zero when risk is found
so the tool composes in shell pipelines and CI gates.
"""

from __future__ import annotations

import json
import sys

import click

from promptguard.models import RiskReport, Severity
from promptguard.scan import scan

# Exit code returned when findings at or above the fail threshold are present.
_EXIT_RISK = 2

_SEVERITY_MARK: dict[Severity, str] = {
    Severity.INFO: "[info]",
    Severity.LOW: "[low ]",
    Severity.MEDIUM: "[med ]",
    Severity.HIGH: "[HIGH]",
}


def _render_human(report: RiskReport) -> str:
    lines: list[str] = []
    lines.append(f"overall: {report.overall.label}  ({len(report.findings)} finding(s))")
    lines.append("")
    if report.is_clean:
        lines.append("No known risk patterns detected.")
    else:
        for finding in report.findings:
            mark = _SEVERITY_MARK[finding.severity]
            lines.append(
                f"{mark} {finding.category}  "
                f"@[{finding.start}:{finding.end}]  {finding.message}"
            )
            lines.append(f"        matched: {finding.matched!r}")
    lines.append("")
    lines.append("redacted:")
    lines.append(report.redacted)
    return "\n".join(lines)


@click.command()
@click.argument("path", required=False, type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Emit the report as JSON.")
@click.option(
    "--fail-on",
    type=click.Choice([s.label for s in Severity], case_sensitive=False),
    default="low",
    show_default=True,
    help="Exit non-zero when a finding at or above this severity is present.",
)
def main(path: str | None, as_json: bool, fail_on: str) -> None:
    """Screen text for prompt-injection and PII risks.

    Reads from PATH if given, otherwise from stdin.
    """
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    else:
        text = sys.stdin.read()

    report = scan(text)

    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        click.echo(_render_human(report))

    threshold = Severity[fail_on.upper()]
    if not report.is_clean and report.overall >= threshold:
        sys.exit(_EXIT_RISK)


if __name__ == "__main__":  # pragma: no cover
    main()

"""Rapport lisible dans le terminal, avec couleurs si possible."""

from __future__ import annotations

from agentguard.models import Severity
from agentguard.scanner import ScanResult

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"


def render_text(result: ScanResult, *, color: bool = False) -> str:
    def paint(text: str, severity: Severity) -> str:
        return f"{_COLORS[severity]}{text}{_RESET}" if color else text

    lines: list[str] = []
    for f in result.findings:
        label = paint(f"[{f.severity.value.upper()}]", f.severity)
        lines.append(f"{label} {f.rule.id} {f.rule.title}")
        lines.append(f"    {f.path}:{f.line}  {f.message}")
        lines.append(f"    Fix: {f.rule.remediation}")
        lines.append("")

    counts = {s: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity] += 1
    summary = ", ".join(f"{counts[s]} {s.value}" for s in reversed(Severity))
    lines.append(
        f"Scanned {result.files_scanned} file(s), skipped {result.files_skipped}. "
        f"{len(result.findings)} finding(s): {summary}."
    )
    if not result.findings:
        lines.append("No issues found.")
    if result.files_skipped:
        # Transparence : « aucun problème » ne vaut que pour ce qui a été lu.
        lines.append(
            f"Note: {result.files_skipped} file(s) or folder(s) could not be analysed "
            "(too large, binary, special or unreadable)."
        )
    return "\n".join(lines)

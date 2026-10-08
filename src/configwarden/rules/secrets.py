"""Règle CW001 : secrets (clés API, tokens) écrits en clair dans un fichier.

Chaque motif (regex) reconnaît le format officiel d'un type de clé.
On reste volontairement strict pour éviter les faux positifs.
"""

from __future__ import annotations

import re

from configwarden.models import Finding, Rule, Severity
from configwarden.redact import redact

HARDCODED_SECRET = Rule(
    id="CW001",
    title="Hardcoded secret",
    severity=Severity.CRITICAL,
    remediation=(
        "Revoke the key immediately in the provider dashboard (deleting the commit is "
        "NOT enough), then load it from an environment variable or a secret manager."
    ),
)

RULES = [HARDCODED_SECRET]

# (nom lisible, motif). Les motifs sont compilés une seule fois (performance).
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}")),
    ("Private key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")),
]


def check_text(text: str, path: str) -> list[Finding]:
    """Cherche des secrets ligne par ligne dans le contenu d'un fichier."""
    findings: list[Finding] = []
    # split("\n") et non splitlines() : ce dernier coupe aussi sur \x0c, \x1c, \u2028…
    # et les numéros de ligne ne correspondraient plus à ceux de l'éditeur ni de GitHub.
    for line_number, line in enumerate(text.split("\n"), start=1):
        for label, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                findings.append(
                    Finding(
                        rule=HARDCODED_SECRET,
                        path=path,
                        line=line_number,
                        # On n'écrit QUE la version masquée du secret.
                        message=f"{label} found: {redact(match.group(0))}",
                    )
                )
    return findings

"""Rapport SARIF 2.1.0 : le format standard des outils d'analyse de sécurité.

GitHub, GitLab, DefectDojo, VS Code (extension SARIF Viewer)… savent le lire.
C'est ce qui rend agentguard *complémentaire* des autres outils plutôt
que concurrent : ses résultats s'affichent dans leurs tableaux de bord.
"""

from __future__ import annotations

import json

from agentguard import __version__
from agentguard.models import Severity
from agentguard.rules import ALL_RULES
from agentguard.scanner import ScanResult

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
# Score utilisé par GitHub pour classer les alertes (0 à 10).
_SECURITY_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}


def render_sarif(result: ScanResult, **_: object) -> str:
    rules = [
        {
            "id": rule.id,
            "name": rule.title.replace(" ", ""),
            "shortDescription": {"text": rule.title},
            "help": {"text": rule.remediation},
            "defaultConfiguration": {"level": _LEVELS[rule.severity]},
            "properties": {
                "security-severity": _SECURITY_SCORE[rule.severity],
                "tags": ["security", "ai-agents"],
            },
        }
        for rule in ALL_RULES
    ]
    results = [
        {
            "ruleId": f.rule.id,
            "level": _LEVELS[f.severity],
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {"startLine": f.line},
                    }
                }
            ],
        }
        for f in result.findings
    ]
    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentguard",
                        "version": __version__,
                        "informationUri": "https://github.com/CHANGE-MOI/agentguard",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)

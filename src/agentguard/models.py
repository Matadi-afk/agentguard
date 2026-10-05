"""Structures de données partagées par tout le projet.

Un « Finding » (constat) = un problème de sécurité trouvé dans un fichier.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum


class Severity(str, Enum):
    """Niveau de gravité d'un constat, du plus faible au plus grave."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Rang numérique, pour comparer : LOW=0 … CRITICAL=3."""
        return list(Severity).index(self)


@dataclass(frozen=True)
class Rule:
    """Description d'une règle de détection (sert aussi au rapport SARIF)."""

    id: str
    title: str
    severity: Severity
    remediation: str


@dataclass(frozen=True)
class Finding:
    """Un problème détecté. `frozen=True` = non modifiable après création."""

    rule: Rule
    path: str  # chemin relatif, avec des "/" (format portable)
    line: int  # numéro de ligne, commence à 1
    message: str  # ne doit JAMAIS contenir un secret en clair

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def to_dict(self) -> dict:
        data = asdict(self)
        data["rule"]["severity"] = self.rule.severity.value
        return data

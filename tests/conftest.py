"""Outils partagés par les tests.

🔐 Les faux secrets sont ASSEMBLÉS à l'exécution (préfixe + remplissage).
Ainsi, aucune chaîne ressemblant à une vraie clé n'existe dans le dépôt :
gitleaks ne bloque pas nos commits, et personne ne peut croire à une fuite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def fake_secret(prefix: str, length: int = 40, alphabet: str = "aB3dE5gH7j") -> str:
    """Construit un faux secret au bon format, ex. fake_secret('ghp_', 36)."""
    body = (alphabet * (length // len(alphabet) + 1))[:length]
    return prefix + body


@pytest.fixture
def write_mcp(tmp_path: Path):
    """Écrit une config MCP dans un dossier temporaire et renvoie son chemin."""

    def _write(servers: dict, name: str = "mcp.json", key: str = "mcpServers") -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({key: servers}, indent=2), encoding="utf-8")
        return path

    return _write

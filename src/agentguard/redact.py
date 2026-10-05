"""Masquage des secrets.

Règle d'or d'un outil de sécurité : un rapport ne doit JAMAIS recopier
un secret en entier. Sinon le rapport (logs CI, fichier SARIF, capture
d'écran) devient lui-même une fuite.
"""

from __future__ import annotations

_VISIBLE_CHARS = 4


def redact(secret: str) -> str:
    """Retourne une version masquée d'un secret.

    >>> redact("sk-ant-abcdefghijklmnop")
    'sk-a****…(23 chars)'
    """
    if len(secret) <= _VISIBLE_CHARS * 2:
        return "****"
    return f"{secret[:_VISIBLE_CHARS]}****…({len(secret)} chars)"

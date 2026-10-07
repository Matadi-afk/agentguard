"""Masquage des secrets et assainissement des textes affichés.

Deux règles d'or d'un outil de sécurité :

1. Un rapport ne doit JAMAIS recopier un secret en entier. Sinon le rapport
   (logs CI, fichier SARIF, capture d'écran) devient lui-même une fuite.
2. Tout texte venant d'un fichier analysé est NON FIABLE. Avant de l'afficher,
   on neutralise les caractères de contrôle : un saut de ligne pourrait créer
   une fausse commande GitHub Actions (« ::error … »), un code ANSI pourrait
   effacer ou maquiller le terminal.
"""

from __future__ import annotations

import re
import unicodedata

_VISIBLE_CHARS = 4

# « schéma://utilisateur:motdepasse@hôte » -> on masque tout ce qui précède « @ ».
_URL_USERINFO = re.compile(r"(?<=://)[^/@\s]+@")

# Caractères Unicode qui inversent l'ordre d'affichage du texte (attaque
# « Trojan Source ») : invisibles mais capables de tromper la lecture.
# Construits avec chr() : un formateur de code ne peut pas les transformer en
# caractères invisibles dans le fichier source lui-même.
_BIDI_CONTROLS = frozenset(
    chr(code)
    for code in (0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E)
    + (0x2066, 0x2067, 0x2068, 0x2069)
)
_NAMED_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def redact(secret: str) -> str:
    """Retourne une version masquée d'un secret.

    >>> redact("sk-ant-abcdefghijklmnop")
    'sk-a****…(23 chars)'
    """
    if len(secret) <= _VISIBLE_CHARS * 2:
        return "****"
    return f"{secret[:_VISIBLE_CHARS]}****…({len(secret)} chars)"


def redact_url(value: str) -> str:
    """Masque les identifiants intégrés à une URL.

    >>> redact_url("git+https://alice:token123@github.com/x/y.git")
    'git+https://****@github.com/x/y.git'

    Une URL sans identifiants, ou un texte qui n'est pas une URL, est renvoyé
    tel quel. On utilise une expression régulière plutôt qu'un analyseur d'URL :
    elle ne peut pas lever d'exception sur une entrée malformée.
    """
    return _URL_USERINFO.sub("****@", value)


def _is_dangerous(char: str) -> bool:
    category = unicodedata.category(char)
    # Cc = contrôles C0/C1 et DEL ; Zl/Zp = séparateurs de ligne/paragraphe.
    return category in {"Cc", "Zl", "Zp"} or char in _BIDI_CONTROLS


def _escape(char: str) -> str:
    if char in _NAMED_ESCAPES:
        return _NAMED_ESCAPES[char]
    code = ord(char)
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def sanitize(text: str) -> str:
    """Rend visibles (et inoffensifs) les caractères de contrôle d'un texte.

    >>> sanitize("evil\\n::error::x")
    'evil\\\\n::error::x'

    Les lettres accentuées et les emojis sont conservés : seuls les caractères
    capables de modifier l'affichage ou de créer une nouvelle ligne sont échappés.
    """
    if not any(_is_dangerous(c) for c in text):
        return text  # cas courant : aucun coût
    return "".join(_escape(c) if _is_dangerous(c) else c for c in text)

"""Lecture du JSON « avec commentaires » (JSONC).

VS Code, Zed, Cursor ou Gemini CLI acceptent dans leurs fichiers de configuration
des commentaires (``// …`` et ``/* … */``) et des virgules finales (``[1, 2,]``).
Un lecteur JSON strict les déclare illisibles : configwarden passerait alors à côté
de configurations bien réelles.

Précautions de sécurité :

- le JSON strict est essayé d'abord et lu tel quel ; le mode JSONC ne sert que si
  le JSON strict échoue ;
- temps de calcul linéaire : expressions régulières « déroulées », sans retour en
  arrière possible, même sur un fichier piégé de 1 Mo ;
- les commentaires deviennent des espaces de même longueur et les virgules finales
  un espace : les positions et les numéros de ligne restent exacts ;
- json.loads reste seul juge de la validité du résultat. Il accepte les caractères
  de contrôle bruts dans les chaînes (strict=False), comme les lecteurs tolérants des
  outils IA : sinon, une simple tabulation suffirait à cacher un fichier à configwarden.
"""

from __future__ import annotations

import json
import re

# Une chaîne JSON, même non terminée (elle s'arrête alors en fin de ligne). Les
# chaînes sont toujours reconnues EN PREMIER : un « // » ou un « /* » à
# l'intérieur d'une chaîne (une URL, par exemple) n'est jamais un commentaire.
_STRING = r'"[^"\\\n]*(?:\\.[^"\\\n]*)*"?'
# Commentaire de bloc, même jamais fermé (il va alors jusqu'à la fin du fichier).
_BLOCK_COMMENT = r"/\*[^*]*(?:\*+[^*/][^*]*)*\**/?"
_LINE_COMMENT = r"//[^\n]*"

_COMMENTS = re.compile(f"({_STRING})|{_LINE_COMMENT}|{_BLOCK_COMMENT}")
_TRAILING_COMMA = re.compile(f"({_STRING})|,(?=\\s*[}}\\]])")
_NOT_LINE_BREAK = re.compile(r"[^\r\n]")


def _blank_comment(match: re.Match[str]) -> str:
    if match.group(1) is not None:
        return match.group(1)  # une chaîne : on la garde intacte
    return _NOT_LINE_BREAK.sub(" ", match.group(0))


def _drop_comma(match: re.Match[str]) -> str:
    return match.group(1) if match.group(1) is not None else " "


def strip(text: str) -> str:
    """Retire commentaires et virgules finales, sans changer aucune position.

    >>> strip('{"a": 1, // note\\n}')
    '{"a": 1         \\n}'
    """
    return _TRAILING_COMMA.sub(_drop_comma, _COMMENTS.sub(_blank_comment, text))


def loads(text: str) -> tuple[object, str]:
    """Lit du JSON strict, ou à défaut du JSONC.

    Renvoie les données et le texte effectivement lu (utile pour retrouver les
    numéros de ligne). Lève ValueError (dont json.JSONDecodeError) ou
    RecursionError si le texte reste illisible.
    """
    try:
        return json.loads(text, strict=False), text
    except (ValueError, RecursionError):
        pass
    clean = strip(text)
    return json.loads(clean, strict=False), clean

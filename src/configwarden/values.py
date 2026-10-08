"""Forme d'une valeur : modèle à remplir, booléen, nombre, mot, chemin de fichier.

Sert à ne pas confondre un exemple de documentation (« sk-... », « <YOUR_KEY> »,
« votre_cle_api ») ou un simple réglage (« 4096 », « true », « oauth ») avec un vrai
secret. Mesuré le 8 octobre 2026 sur 3 099 exemples publiés : ces cas faisaient
l'essentiel des fausses alertes de CW103.

Performance : expressions sans imbrication ambiguë, quantités bornées, et on ne
regarde que le début d'une valeur très longue (un fichier piégé peut en contenir).
"""

from __future__ import annotations

import re

# Au-delà, une valeur n'est examinée que sur ses premiers caractères.
_SCAN_LIMIT = 4096

# Marques d'un modèle à remplir, cherchées N'IMPORTE OÙ dans la valeur. Choisies pour
# qu'un vrai jeton aléatoire ne les contienne presque jamais (revue du 8 octobre 2026) :
# « xxx » en minuscules ou majuscules (pas « xXx »), mots de langue en DÉBUT de valeur.
_PLACEHOLDER_MARKERS = re.compile(
    r"<[^<>]{0,64}>"  # <YOUR_KEY>
    r"|\{\{[^{}]{0,64}\}\}|\{[A-Za-z_][A-Za-z0-9_]{0,63}\}"  # {{API_KEY}}, {DB_PASSWORD}
    r"|\[[^\[\]]{1,64}\]"  # [YOUR KEY]
    r"|(?-i:xxx|XXX)|\*{3}|#{4}|\.{3}|…"  # sk_xxx, ****, ..., …
    r"|example|placeholder|dummy|sample|redacted"
    r"|change[-_ ]?me|replace[-_ ]?(?:me|with|this)|fill[-_ ]?(?:in|me)|insert[-_ ]"
    r"|your[-_ ]?[a-z0-9]|(?:^|[-_ ])(?:here|aqui|ici|hier|todo|tbd|optional)(?:$|[-_ ])"
    # « votre clé », « tu clave », « sua chave », « dein Token », « il tuo token »…
    r"|votre|^(?:ta|ton|tu|tus|seu|sua|dein|deine|ihr|il[-_ ]tuo|la[-_ ]tua)[-_ ]",
    re.IGNORECASE,
)
# Valeur d'exemple d'un format de clé connu (CW001) : marques sans ambiguïté seulement,
# pour ne jamais écarter un vrai jeton (« ghp_…xXx… » reste signalé).
_EXAMPLE_TOKEN = re.compile(r"xxxx|XXXX|\.{3}|…|\*{3}|EXAMPLE|[Ee]xample|<|YOUR|[Yy]our")
# Écritures non latines (CJK, cyrillique, arabe…) : un texte d'exemple, pas un jeton. Les
# lettres accentuées latines (« Sécurité ») peuvent faire partie d'un vrai mot de passe.
_LAST_LATIN_LETTER = 0x024F
# Nom de variable écrit à la place de la valeur : « PATH_TO_CREDENTIALS », « APP_SECRET ».
_CONSTANT_NAME = re.compile(r"[A-Z][A-Z0-9]{0,63}(?:_[A-Z0-9]{1,64}){1,15}")
_BOOLEAN = re.compile(r"true|false|yes|no|on|off|y|n|enabled?|disabled?|none|null|nil", re.I)
# Nombre court : un port, une limite, une durée (pas un long identifiant numérique).
_NUMBER = re.compile(r"[+-]?\d{1,12}(?:\.\d{1,12})?")
# Quelques mots sans chiffre (« oauth », « client_credentials », « notion_api_key »,
# « My API Key ») : une option ou un exemple, pas un jeton.
_WORD = re.compile(r"[A-Za-z]{1,24}(?:[-_. ][A-Za-z]{1,24}){0,3}")
_WORD_MAX_LENGTH = 40
# Début propre à un chemin : ~/, ./, ../, C:\, \\serveur, %VAR%\, ${VAR}/, $VAR/
_PATH_PREFIX = re.compile(
    r"~[\\/]|\.{1,2}[\\/]|[A-Za-z]:[\\/]|\\\\|%[A-Za-z_][A-Za-z0-9_]{0,63}%[\\/]"
    r"|\$\{?[A-Za-z_][A-Za-z0-9_]{0,63}\}?[\\/]"
)
_FILE_EXTENSION = re.compile(r"\.[A-Za-z][A-Za-z0-9]{0,7}\Z")


def is_placeholder(value: str) -> bool:
    """Modèle à remplir : « <YOUR_KEY> », « sk-... », « ghp_xxxx », « votre_cle »…"""
    head = value[:_SCAN_LIMIT]
    if _PLACEHOLDER_MARKERS.search(head) or _CONSTANT_NAME.fullmatch(head.strip()):
        return True
    # Lettres non latines (« 你的密钥 ») : texte écrit par un humain, pas un jeton.
    return not head.isascii() and any(
        ord(char) > _LAST_LATIN_LETTER and char.isalpha() for char in head
    )


def is_example_token(token: str) -> bool:
    """Valeur d'exemple d'un format de clé connu : « sk-ant-xxxx… », « AKIA…EXAMPLE »."""
    return bool(_EXAMPLE_TOKEN.search(token[:_SCAN_LIMIT]))


def is_boolean(value: str) -> bool:
    return bool(_BOOLEAN.fullmatch(value.strip()))


def is_number(value: str) -> bool:
    return bool(_NUMBER.fullmatch(value.strip()))


def is_word(value: str) -> bool:
    """Un ou deux mots en lettres seulement (une option, pas un jeton)."""
    value = value.strip()
    return len(value) <= _WORD_MAX_LENGTH and bool(_WORD.fullmatch(value))


def is_file_path(value: str, *, path_hint: bool = False) -> bool:
    """Chemin d'un fichier ou d'un dossier, et non son contenu.

    « ~/ », « ./ », « C:\\ »… suffisent. Sinon il faut un séparateur ET un indice : une
    extension (« data/key.json »), un dossier caché (« /home/a/.ssh/id_rsa »), ou une
    clé qui annonce un chemin (`path_hint`). Un secret en base64 peut contenir « / »,
    mais jamais de point.
    """
    value = value.strip()
    if _PATH_PREFIX.match(value):
        return True
    if "/" not in value and "\\" not in value:
        return False
    if _FILE_EXTENSION.search(value[-9:]):
        return True
    return value.startswith("/") and (path_hint or "/." in value)

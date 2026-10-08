"""Gestion sécurisée des secrets de l'application (clés API, licence…).

Pas utilisé avant l'étape 8, mais posé dès maintenant pour avoir les bons
réflexes :

1. Les secrets viennent des VARIABLES D'ENVIRONNEMENT, jamais du code.
2. Un secret est enveloppé dans `Secret` : si on l'affiche ou le logue
   par erreur, on voit `Secret('****')` au lieu de la vraie valeur.
3. On lit la vraie valeur uniquement au moment précis où on en a besoin,
   via `.reveal()`. Ce mot explicite rend les fuites faciles à repérer en
   relecture de code.
"""

from __future__ import annotations

import hmac
import os


class MissingSecretError(RuntimeError):
    """Levée quand un secret obligatoire est absent."""


class Secret:
    """Conteneur qui protège une valeur sensible contre l'affichage accidentel."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """Renvoie la vraie valeur. À n'utiliser qu'au dernier moment."""
        return self._value

    def __repr__(self) -> str:
        return "Secret('****')"

    __str__ = __repr__

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        # Comparaison à temps constant : évite les attaques par mesure du temps.
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    __hash__ = None  # type: ignore[assignment]  # un secret ne doit pas servir de clé

    def __reduce__(self):
        # Empêche de sérialiser (pickle) un secret par mégarde.
        raise TypeError("Secret objects cannot be serialized")


def get_secret(name: str, *, required: bool = False) -> Secret | None:
    """Lit un secret depuis une variable d'environnement.

    Les espaces autour sont retirés (erreur de copier-coller fréquente).
    Une valeur vide est traitée comme absente.
    """
    value = os.environ.get(name, "").strip()
    if not value:
        if required:
            # Le message cite le NOM de la variable, jamais une valeur.
            raise MissingSecretError(
                f"La variable d'environnement {name} est requise mais absente. "
                "Ajoute-la dans ton fichier .env (voir .env.example)."
            )
        return None
    return Secret(value)

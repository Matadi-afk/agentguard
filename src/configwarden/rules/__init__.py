"""Toutes les règles de détection, regroupées en un seul endroit."""

from configwarden.models import Rule
from configwarden.rules import mcp, secrets

ALL_RULES: list[Rule] = [*secrets.RULES, *mcp.RULES]

__all__ = ["ALL_RULES", "mcp", "secrets"]

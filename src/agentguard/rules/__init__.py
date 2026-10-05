"""Toutes les règles de détection, regroupées en un seul endroit."""

from agentguard.models import Rule
from agentguard.rules import mcp, secrets

ALL_RULES: list[Rule] = [*secrets.RULES, *mcp.RULES]

__all__ = ["ALL_RULES", "mcp", "secrets"]

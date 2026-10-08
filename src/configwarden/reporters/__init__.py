"""Formats de sortie : texte (humain), JSON (scripts), SARIF (GitHub Security)."""

from configwarden.reporters.json_reporter import render_json
from configwarden.reporters.sarif import render_sarif
from configwarden.reporters.text import render_text

RENDERERS = {"text": render_text, "json": render_json, "sarif": render_sarif}

__all__ = ["RENDERERS", "render_json", "render_sarif", "render_text"]

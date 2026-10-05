"""Rapport JSON, pratique pour d'autres scripts ou outils."""

from __future__ import annotations

import json

from agentguard import __version__
from agentguard.scanner import ScanResult


def render_json(result: ScanResult, **_: object) -> str:
    payload = {
        "tool": "agentguard",
        "version": __version__,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)

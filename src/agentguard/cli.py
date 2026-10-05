"""Interface en ligne de commande.

Exemples :
    agentguard scan .
    agentguard scan . --format sarif --output agentguard.sarif
    agentguard scan . --fail-on high --exclude "examples/*"
    agentguard rules

Codes de sortie (utiles en CI) :
    0 = aucun problème au niveau demandé
    1 = au moins un problème >= --fail-on
    2 = erreur d'utilisation (chemin introuvable…)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from agentguard import __version__
from agentguard.models import Severity
from agentguard.reporters import RENDERERS
from agentguard.rules import ALL_RULES
from agentguard.scanner import scan

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="Security scanner for AI agent configurations (MCP, secrets).",
    )
    parser.add_argument("--version", action="version", version=f"agentguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="Scan a file or a directory.")
    scan_cmd.add_argument("path", nargs="?", default=".", help="File or directory (default: .)")
    scan_cmd.add_argument("--format", choices=sorted(RENDERERS), default="text")
    scan_cmd.add_argument("--output", "-o", help="Write the report to this file instead of stdout.")
    scan_cmd.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default="low",
        help="Minimum severity that makes the command exit with code 1 (default: low).",
    )
    scan_cmd.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help='Glob to skip, repeatable (e.g. --exclude "tests/*").',
    )

    sub.add_parser("rules", help="List all detection rules.")
    return parser


def _use_color(stream) -> bool:
    # Convention https://no-color.org : NO_COLOR désactive les couleurs.
    return stream.isatty() and "NO_COLOR" not in os.environ


def _cmd_rules() -> int:
    for rule in ALL_RULES:
        print(f"{rule.id}  [{rule.severity.value:<8}] {rule.title}")
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        result = scan(args.path, excludes=args.exclude)
    except FileNotFoundError as error:
        print(f"agentguard: error: {error}", file=sys.stderr)
        return EXIT_ERROR

    to_file = bool(args.output)
    report = RENDERERS[args.format](result, color=not to_file and _use_color(sys.stdout))

    if to_file:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(f"Report written to {args.output} ({len(result.findings)} finding(s)).")
    else:
        print(report)

    threshold = Severity(args.fail_on).rank
    failing = any(f.severity.rank >= threshold for f in result.findings)
    return EXIT_FINDINGS if failing else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "rules":
        return _cmd_rules()
    return _cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())

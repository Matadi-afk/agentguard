"""Interface en ligne de commande.

Exemples :
    configwarden scan .
    configwarden scan . --format sarif --output configwarden.sarif
    configwarden scan . --fail-on high --exclude "examples/*"
    configwarden rules

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

from configwarden import __version__
from configwarden.models import Severity
from configwarden.redact import sanitize
from configwarden.reporters import RENDERERS
from configwarden.rules import ALL_RULES
from configwarden.scanner import scan

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="configwarden",
        description="Security scanner for AI agent configurations (MCP, secrets).",
    )
    parser.add_argument("--version", action="version", version=f"configwarden {__version__}")
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


def _symlink_on_the_way(path: Path, roots: list[Path]) -> bool:
    """Un des dossiers traversés (sous le dossier courant ou le dossier scanné),
    ou le fichier lui-même, est-il un lien symbolique ?"""
    target = Path(os.path.abspath(path))
    for root in roots:
        base = Path(os.path.abspath(root))
        try:
            relative = target.relative_to(base)
        except ValueError:
            continue
        current = base
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                return True
    return target.is_symlink()


def _write_report(path: Path, report: str, roots: list[Path]) -> None:
    """Écrit le rapport sans jamais suivre un lien symbolique.

    Sécurité : en CI, le rapport est écrit DANS le dépôt analysé, qui n'est pas
    fiable. Un lien « configwarden.sarif -> ../../fichier » ferait écraser un autre
    fichier de la machine, tout comme un dossier « reports -> ../.. ».
    O_NOFOLLOW (Linux, macOS) protège aussi le dernier élément pendant l'ouverture.
    """
    if ".." in path.parts:
        # « reports/../x » : le système suit d'abord « reports » (peut-être un lien)
        # avant de remonter. Impossible à vérifier sans ambiguïté : on refuse.
        raise OSError(f"refusing an output path that contains '..': {path}")
    if _symlink_on_the_way(path, roots):
        raise OSError(f"refusing to write the report through a symbolic link: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8", errors="backslashreplace") as handle:
        handle.write(report + "\n")


def _protect_console() -> None:
    """Un caractère impossible à afficher ne doit jamais faire planter le rapport."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def _cmd_rules() -> int:
    for rule in ALL_RULES:
        print(f"{rule.id}  [{rule.severity.value:<8}] {rule.title}")
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        result = scan(args.path, excludes=args.exclude)
    except FileNotFoundError as error:
        print(f"configwarden: error: {sanitize(str(error))}", file=sys.stderr)
        return EXIT_ERROR

    to_file = bool(args.output)
    report = RENDERERS[args.format](result, color=not to_file and _use_color(sys.stdout))

    if to_file:
        try:
            _write_report(Path(args.output), report, roots=[Path.cwd(), Path(args.path)])
        except OSError as error:
            print(f"configwarden: error: {sanitize(str(error))}", file=sys.stderr)
            return EXIT_ERROR
        shown = sanitize(args.output)
        print(f"Report written to {shown} ({len(result.findings)} finding(s)).")
    else:
        print(report)

    threshold = Severity(args.fail_on).rank
    failing = any(f.severity.rank >= threshold for f in result.findings)
    return EXIT_FINDINGS if failing else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    _protect_console()
    args = _build_parser().parse_args(argv)
    if args.command == "rules":
        return _cmd_rules()
    return _cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())

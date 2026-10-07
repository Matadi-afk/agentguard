"""Le moteur : parcourt les fichiers d'un dossier et applique les règles.

Précautions de sécurité du parcours :
- on ne suit PAS les liens symboliques (un lien piégé pourrait faire lire
  des fichiers hors du projet, ou boucler à l'infini) ;
- on ne lit que les fichiers ordinaires (un « tube » FIFO bloquerait le scan) ;
- on ignore les fichiers trop gros et les fichiers binaires ;
- un fichier ou un dossier illisible est sauté (et compté) sans faire planter le scan.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from agentguard.models import Finding
from agentguard.rules import mcp, secrets

MAX_FILE_SIZE = 1_000_000  # 1 Mo
_BINARY_SNIFF_SIZE = 8192

DEFAULT_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0


def _is_excluded(relative: PurePosixPath, patterns: Iterable[str]) -> bool:
    text = relative.as_posix()
    return any(fnmatch.fnmatch(text, p) or fnmatch.fnmatch(relative.name, p) for p in patterns)


def iter_files(
    root: Path,
    excludes: Iterable[str] = (),
    on_error: Callable[[OSError], None] | None = None,
) -> Iterator[Path]:
    """Liste les fichiers à analyser, sans suivre les liens symboliques.

    `on_error` est appelé pour chaque dossier illisible : sans lui, os.walk les
    ignorerait en silence et le rapport dirait « No issues found » à tort.
    """
    excludes = list(excludes)
    if root.is_file():
        yield root
        return
    for current, dirnames, filenames in os.walk(root, onerror=on_error, followlinks=False):
        current_path = Path(current)
        # Modifier `dirnames` sur place empêche os.walk de descendre dans ces dossiers.
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in DEFAULT_IGNORED_DIRS
            and not (current_path / d).is_symlink()
            and not _is_excluded(
                PurePosixPath((current_path / d).relative_to(root).as_posix()), excludes
            )
        )
        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink():
                continue
            relative = PurePosixPath(path.relative_to(root).as_posix())
            if not _is_excluded(relative, excludes):
                yield path


def _read_text(path: Path) -> str | None:
    """Lit un fichier texte, ou renvoie None s'il faut l'ignorer."""
    try:
        info = path.stat()
        # Seulement les fichiers ordinaires : un tube (FIFO) ou un périphérique
        # bloquerait la lecture indéfiniment.
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_SIZE:
            return None
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_SIZE + 1)  # lecture bornée, même si le fichier grossit
    except OSError:
        return None
    if len(raw) > MAX_FILE_SIZE or b"\0" in raw[:_BINARY_SNIFF_SIZE]:  # octet nul = binaire
        return None
    # « utf-8-sig » retire l'éventuel BOM : sinon json.loads refuserait le fichier et
    # une configuration dangereuse échapperait à l'analyse.
    return raw.decode("utf-8-sig", errors="replace")


def scan(target: str | Path, excludes: Iterable[str] = ()) -> ScanResult:
    """Analyse un fichier ou un dossier et renvoie tous les constats."""
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {target}")
    base = root.parent if root.is_file() else root

    result = ScanResult()

    def count_unreadable_directory(_error: OSError) -> None:
        result.files_skipped += 1

    for path in iter_files(root, excludes, on_error=count_unreadable_directory):
        text = _read_text(path)
        if text is None:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        relative = PurePosixPath(path.relative_to(base).as_posix())
        rel_str = relative.as_posix()

        result.findings.extend(secrets.check_text(text, rel_str))
        if mcp.is_mcp_config(relative):
            result.findings.extend(mcp.check_text(text, rel_str))

    # Tri : le plus grave d'abord, puis par fichier et ligne.
    result.findings.sort(key=lambda f: (-f.severity.rank, f.path, f.line, f.rule.id))
    return result

"""Tests de durcissement : agentguard face à des fichiers MALVEILLANTS.

Un outil de sécurité lit des fichiers écrits par n'importe qui. Ces tests
reproduisent trois attaques trouvées lors de la revue de sécurité du
7 octobre 2026, corrigées en version 0.2.1 :

- V1 : fuite d'identifiants (« user:token@ ») recopiés dans les rapports ;
- V2 : injection de caractères de contrôle dans la sortie (sauts de ligne,
  codes ANSI, commandes de workflow GitHub Actions « ::… ») ;
- V3 : plantage du scan sur un JSON imbriqué à l'extrême (déni de service).
"""

import json

import pytest

from agentguard.cli import main
from agentguard.models import Finding
from agentguard.redact import redact_url, sanitize
from agentguard.reporters.text import render_text
from agentguard.rules import mcp
from agentguard.rules.mcp import INSECURE_TRANSPORT
from agentguard.scanner import ScanResult, scan
from tests.conftest import fake_secret

# Faux identifiant assemblé à l'exécution (jamais écrit en clair dans le dépôt).
FAKE_TOKEN = fake_secret("tok", 24)

# Caractères invisibles construits avec chr() : jamais écrits tels quels dans
# le code source (un formateur pourrait les « dé-échapper »).
RLO = chr(0x202E)  # inverse le sens d'affichage (attaque « Trojan Source »)
LINE_SEP = chr(0x2028)  # séparateur de ligne Unicode


# --- V1 : identifiants dans les URL ---------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("git+https://alice:SECRET@github.com/x/y.git", "git+https://****@github.com/x/y.git"),
        ("https://SECRET@example.com/pkg.tgz", "https://****@example.com/pkg.tgz"),
        ("https://example.com/pkg.tgz", "https://example.com/pkg.tgz"),
        ("github:someone/repo", "github:someone/repo"),
        ("git@github.com:someone/repo.git", "git@github.com:someone/repo.git"),
        ("@scope/pkg@1.2.3", "@scope/pkg@1.2.3"),
    ],
)
def test_redact_url(url, expected) -> None:
    assert redact_url(url) == expected


@pytest.mark.parametrize(
    "args",
    [
        ["-y", f"git+https://alice:{FAKE_TOKEN}@github.com/x/y.git"],
        ["-y", f"https://{FAKE_TOKEN}@example.com/server-1.0.0.tgz"],
    ],
)
def test_credentials_in_package_url_never_reach_any_report(write_mcp, tmp_path, capsys, args):
    path = write_mcp({"s": {"command": "npx", "args": args}})
    for fmt in ("text", "json", "sarif"):
        main(["scan", str(path), "--format", fmt])
        out = capsys.readouterr().out
        assert FAKE_TOKEN not in out, f"token leaked in {fmt} output"
        assert "****@" in out


def test_credentials_in_uvx_from_are_redacted(write_mcp) -> None:
    args = ["--from", f"git+https://bob:{FAKE_TOKEN}@gitlab.com/x/y", "server"]
    findings = scan(write_mcp({"s": {"command": "uvx", "args": args}})).findings
    assert [f.rule.id for f in findings] == ["AG107"]
    assert FAKE_TOKEN not in findings[0].message


# --- V2 : caractères de contrôle dans la sortie ---------------------------------

HOSTILE_NAME = "evil\n::error title=PWNED::fake\r\x1b[2J\x1b]52;c;ZXZpbA==\x07" + RLO


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("normal text", "normal text"),
        ("a\nb", "a\\nb"),
        ("a\rb\tc", "a\\rb\\tc"),
        ("\x1b[31m", "\\x1b[31m"),
        ("\x7f", "\\x7f"),
        ("\x9b", "\\x9b"),
        (f"abc{RLO}def", "abc\\u202edef"),
        (f"line{LINE_SEP}sep", "line\\u2028sep"),
        ("accents éàü 🔒", "accents éàü 🔒"),
    ],
)
def test_sanitize(raw, expected) -> None:
    assert sanitize(raw) == expected


def test_finding_message_and_path_are_sanitized_at_creation() -> None:
    finding = Finding(rule=INSECURE_TRANSPORT, path="a\nb.json", line=1, message="x\x1by")
    assert finding.path == "a\\nb.json"
    assert finding.message == "x\\x1by"


def test_hostile_server_name_cannot_inject_lines_or_escape_codes(write_mcp) -> None:
    path = write_mcp({HOSTILE_NAME: {"url": "http://evil.example"}})
    result = scan(path)
    assert [f.rule.id for f in result.findings] == ["AG105"]
    for color in (False, True):
        out = render_text(result, color=color)
        # Aucune ligne ne peut commencer par une commande de workflow GitHub Actions.
        assert not any(line.lstrip().startswith("::") for line in out.splitlines())
        # Aucun code d'échappement injecté (les seuls autorisés sont nos couleurs).
        assert "\x1b[2J" not in out and "\x1b]52" not in out and RLO not in out


def test_hostile_file_path_is_sanitized_in_text_report() -> None:
    finding = Finding(rule=INSECURE_TRANSPORT, path="x\n::warning::y.json", line=1, message="m")
    out = render_text(ScanResult(findings=[finding], files_scanned=1))
    assert not any(line.lstrip().startswith("::") for line in out.splitlines())


# --- V3 : déni de service par JSON trop imbriqué --------------------------------


def test_deeply_nested_json_does_not_crash_the_scan(tmp_path) -> None:
    depth = 200_000
    (tmp_path / "mcp.json").write_text("[" * depth + "]" * depth, encoding="utf-8")
    (tmp_path / "app.py").write_text("token = '" + fake_secret("ghp_", 36) + "'\n")
    ids = sorted(f.rule.id for f in scan(tmp_path).findings)
    # Le fichier piégé est signalé comme illisible ET le reste du projet est analysé.
    assert ids == ["AG001", "AG100"]


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "null",
        '"just a string"',
        '{"mcpServers": null}',
        '{"mcpServers": {"a": 5}}',
        '{"mcp": 3}',
        '{"servers": {"a": {"args": "notalist", "env": [1, 2]}}}',
        '{"mcpServers": {"a": {"command": 7, "url": 9, "alwaysAllow": "x", "trust": "yes"}}}',
        '{"mcpServers": {"a": {"command": "docker", "args": ["run", "-v"]}}}',
        '{"mcpServers": {"a": {"command": "npx", "args": ["--from"]}}}',
    ],
)
def test_malformed_but_valid_json_never_crashes(text) -> None:
    mcp.check_text(text, "mcp.json")  # ne doit lever aucune exception


def test_sarif_output_stays_valid_json_with_hostile_input(write_mcp, capsys) -> None:
    path = write_mcp({HOSTILE_NAME: {"url": "http://evil.example"}})
    main(["scan", str(path), "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "AG105"


# --- Garde-fou permanent : pas de caractères invisibles dans notre propre code ---


def test_no_invisible_or_bidi_characters_in_source() -> None:
    """Empêche une attaque « Trojan Source » contre agentguard lui-même."""
    from pathlib import Path

    from agentguard.redact import sanitize as _sanitize

    root = Path(__file__).resolve().parent.parent
    offenders = []
    for path in [*root.glob("src/**/*.py"), *root.glob("tests/**/*.py")]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _sanitize(line.replace("\t", " ")) != line.replace("\t", " "):
                offenders.append(f"{path.name}:{number}")
    assert offenders == []

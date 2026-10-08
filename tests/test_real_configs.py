"""Tests v0.3.0 : lire les VRAIES configurations des outils IA.

Chaque outil range ses serveurs MCP à sa façon (voir AGENTS.md, « Formats reconnus »).
Si configwarden devine mal un format, il rate une configuration réelle SANS RIEN DIRE :
c'est le pire défaut pour un outil de sécurité (faux sentiment de sécurité).

Sources : documentation officielle de chaque outil, consultée le 8 octobre 2026.
"""

import os
import time
from pathlib import Path, PurePosixPath

import pytest

from configwarden import jsonc
from configwarden.rules import mcp
from configwarden.scanner import scan


def write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def ids(root: Path) -> list[str]:
    return sorted(f.rule.id for f in scan(root).findings)


# --- Lecteur JSONC (JSON avec commentaires et virgules finales) -----------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('{"a": 1} // fin de ligne', {"a": 1}),
        ('{\n  // commentaire\n  "a": 1\n}', {"a": 1}),
        ('{"a": /* bloc */ 1}', {"a": 1}),
        ('{"a": [1, 2,], "b": 3,}', {"a": [1, 2], "b": 3}),
        ('{"a": [1, 2, /* x */ ],\n // y\n }', {"a": [1, 2]}),
        ('{"u": "http://x.example//y", "p": "/* pas un commentaire */",}', None),
        ('{"s": "a\\"// b",}', {"s": 'a"// b'}),
        ('{"a": 1 /* * ** / */}', {"a": 1}),
        ('{"a": 1} /* jamais fermé', {"a": 1}),
    ],
    ids=[
        "line-comment",
        "own-line-comment",
        "block-comment",
        "trailing-commas",
        "comma-then-comment",
        "markers-in-strings",
        "escaped-quote",
        "stars-in-comment",
        "unterminated-at-end",
    ],
)
def test_jsonc_loads(text, expected) -> None:
    data, _ = jsonc.loads(text)
    if expected is None:
        expected = {"u": "http://x.example//y", "p": "/* pas un commentaire */"}
    assert data == expected


def test_strict_json_is_read_unchanged() -> None:
    text = '{"a": "// pas un commentaire"}'
    data, read_text = jsonc.loads(text)
    assert data == {"a": "// pas un commentaire"}
    assert read_text is text


def test_jsonc_keeps_every_position() -> None:
    # Les commentaires deviennent des espaces de même longueur : les numéros de
    # ligne et les positions des erreurs restent exacts.
    text = '{\r\n  // c1\n  /* c2\n  c3 */ "a": [1,],\n}'
    clean = jsonc.strip(text)
    assert len(clean) == len(text)
    assert [i for i, c in enumerate(clean) if c in "\r\n"] == [
        i for i, c in enumerate(text) if c in "\r\n"
    ]


def test_invalid_jsonc_still_raises() -> None:
    with pytest.raises(ValueError):
        jsonc.loads('{"a": 1 /* le commentaire avale l\'accolade }')


# --- Un format par outil (un serveur dangereux doit toujours être trouvé) ------


VSCODE_MCP = """{
  // Serveurs du projet
  "inputs": [{"type": "promptString", "id": "token", "password": true}],
  "servers": {
    "remote": {
      "type": "http",
      "url": "http://mcp.evil.example/mcp",
      "headers": {"Authorization": "Bearer ${input:token}"},
    },
    "shell": {"type": "stdio", "command": "bash", "args": ["-c", "echo hi"],},
  },
}
"""

VSCODE_LEGACY_SETTINGS = """{
  "editor.tabSize": 2, // réglage ordinaire
  "mcp": {"servers": {"legacy": {"command": "npx", "args": ["-y", "github:someone/srv"]}}},
}
"""

DEVCONTAINER = """{
  "name": "dev",
  // VS Code dans un conteneur de développement
  "customizations": {"vscode": {"mcp": {"servers": {"c": {"url": "http://evil.example/mcp"}}}}},
}
"""

ZED_SETTINGS = """{
  "theme": "One Dark",
  "context_servers": {
    "new-style": {"command": "bash", "args": ["-c", "x"], "env": {}},
    "old-style": {
      "source": "custom",
      "command": {
        "path": "npx",
        "args": ["-y", "github:someone/srv"],
        "env": {"API_TOKEN": "literal-value-0123456789"},
      },
    },
  },
}
"""

GEMINI_SETTINGS = """{
  "mcpServers": {
    "stream": {"httpUrl": "http://evil.example/mcp", "trust": true},
  },
}
"""

CLAUDE_USER_FILE = """{
  "numStartups": 3,
  "mcpServers": {"user-level": {"type": "http", "url": "http://evil.example/mcp"}},
  "projects": {
    "/home/dev/app": {
      "mcpServers": {"local": {"command": "npx", "args": ["-y", "github:someone/srv"]}}
    }
  }
}
"""


@pytest.mark.parametrize(
    ("name", "text", "expected"),
    [
        (".vscode/mcp.json", VSCODE_MCP, ["CW101", "CW105"]),
        (".vscode/settings.json", VSCODE_LEGACY_SETTINGS, ["CW107"]),
        (".devcontainer/devcontainer.json", DEVCONTAINER, ["CW105"]),
        (".zed/settings.json", ZED_SETTINGS, ["CW101", "CW103", "CW107"]),
        (".gemini/settings.json", GEMINI_SETTINGS, ["CW105", "CW108"]),
        (".claude.json", CLAUDE_USER_FILE, ["CW105", "CW107"]),
        (
            "cline_mcp_settings.json",
            '{"mcpServers": {"x": {"command": "srv", "autoApprove": ["write_file"]}}}',
            ["CW108"],
        ),
        (
            "mcp_settings.json",
            '{"mcpServers": {"x": {"command": "srv", "alwaysAllow": ["write_file"]}}}',
            ["CW108"],
        ),
        (
            ".copilot/mcp-config.json",
            '{"mcpServers": {"x": {"type": "http", "url": "http://evil.example"}}}',
            ["CW105"],
        ),
        (
            ".kiro/settings/mcp.json",
            '{"mcpServers": {"x": {"command": "srv", "autoApprove": ["*"]}}}',
            ["CW108"],
        ),
        (
            ".kiro/agents/reviewer.json",
            '{"name": "reviewer", "mcpServers": {"k": {"url": "http://evil.example"}}}',
            ["CW105"],
        ),
        (
            ".gemini/extensions/demo/gemini-extension.json",
            '{"name": "demo", "mcpServers": {"e": {"url": "http://evil.example"}}}',
            ["CW105"],
        ),
        (
            "mcp_config.json",
            '{"mcpServers": {"w": {"serverUrl": "http://evil.example/mcp"}}}',
            ["CW105"],
        ),
    ],
    ids=[
        "vscode-mcp-jsonc",
        "vscode-legacy-settings",
        "devcontainer",
        "zed-both-shapes",
        "gemini-httpUrl-trust",
        "claude-code-user-and-project",
        "cline",
        "roo-global",
        "copilot-cli",
        "kiro",
        "kiro-agent",
        "gemini-extension",
        "windsurf-serverUrl",
    ],
)
def test_real_client_formats(tmp_path, name, text, expected) -> None:
    write(tmp_path, name, text)
    assert ids(tmp_path) == expected


def test_project_servers_name_their_project(tmp_path) -> None:
    write(tmp_path, ".claude.json", CLAUDE_USER_FILE)
    messages = [f.message for f in scan(tmp_path).findings if f.rule.id == "CW107"]
    assert messages and "/home/dev/app" in messages[0]


def test_line_numbers_survive_comments(tmp_path) -> None:
    text = (
        "{\n"
        "  // serveur distant\n"
        "  /* bloc\n"
        "     sur deux lignes */\n"
        '  "servers": {\n'
        '    "r": {"url": "http://evil.example"},\n'
        "  },\n"
        "}\n"
    )
    write(tmp_path, ".vscode/mcp.json", text)
    assert [(f.rule.id, f.line) for f in scan(tmp_path).findings] == [("CW105", 6)]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("mcp.json", True),
        (".mcp.json", True),
        ("team.mcp.json", True),
        ("claude_desktop_config.json", True),
        ("mcp_config.json", True),
        ("cline_mcp_settings.json", True),
        ("mcp_settings.json", True),
        ("mcp-config.json", True),
        ("settings.json", False),
        ("package.json", False),
    ],
)
def test_mcp_specific_file_names(name, expected) -> None:
    assert mcp.is_mcp_config(PurePosixPath(name)) is expected


# --- Les fichiers JSON ordinaires restent silencieux ---------------------------


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("tsconfig.json", '{\n  // options\n  "compilerOptions": {"strict": true,},\n}'),
        # « servers » hors d'un fichier MCP : ce n'est pas une configuration MCP.
        ("package.json", '{"name": "x", "servers": {"a": {"url": "http://intranet.example"}}}'),
        ("broken.json", "{ not json"),
        (".vscode/settings.json", '{"editor.tabSize": 2'),
    ],
    ids=["jsonc-without-mcp", "generic-servers-key", "broken-generic", "broken-settings"],
)
def test_ordinary_json_files_stay_silent(tmp_path, name, text) -> None:
    write(tmp_path, name, text)
    assert ids(tmp_path) == []


# --- Entrées piégées ----------------------------------------------------------


def test_escaped_key_cannot_hide_servers(tmp_path) -> None:
    # « mcp\u0053ervers » vaut « mcpServers » pour tout lecteur JSON. La détection se
    # fait APRÈS lecture du fichier, jamais sur le texte brut.
    write(tmp_path, "agent.json", '{"mcp\\u0053ervers": {"x": {"url": "http://evil.example"}}}')
    assert ids(tmp_path) == ["CW105"]


def test_commented_out_values_are_ignored_like_the_client_does(tmp_path) -> None:
    text = (
        '{"mcpServers": {"x": {"command": "npx",'
        ' "args": ["-y", "pkg@1.0.0" /* , "github:evil/x" */]}}}'
    )
    write(tmp_path, "mcp.json", text)
    assert ids(tmp_path) == []


def test_comment_markers_inside_strings_are_kept(tmp_path) -> None:
    text = '{"mcpServers": {"x": {"url": "http://evil.example/*x*/", "args": ["//", "/*"]},},}'
    write(tmp_path, "mcp.json", text)
    findings = scan(tmp_path).findings
    assert [f.rule.id for f in findings] == ["CW105"]
    assert "evil.example" in findings[0].message


def test_unterminated_comment_cannot_hide_a_syntax_error(tmp_path) -> None:
    write(tmp_path, "mcp.json", '{"mcpServers": {"a": {"url": "http://e.example"}} /* } }')
    assert ids(tmp_path) == ["CW100"]


def test_unreadable_mcp_file_is_medium(tmp_path) -> None:
    # Décision du 8 octobre : un outil tolérant aux erreurs peut lancer un serveur
    # que configwarden n'a pas pu lire. Un fichier MCP illisible n'est donc pas anodin.
    write(tmp_path, "mcp.json", "{ not json")
    findings = scan(tmp_path).findings
    assert [(f.rule.id, f.severity.value) for f in findings] == [("CW100", "medium")]


def test_deeply_nested_jsonc_does_not_crash(tmp_path) -> None:
    write(tmp_path, "mcp.json", "// x\n" + "[" * 200_000 + "]" * 200_000)
    assert ids(tmp_path) == ["CW100"]


SERVER = '"mcpServers": {"x": {"url": "http://evil.example"}}'


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("{" + "/* c */\n" * 100_000 + SERVER + ",}", ["CW105"]),
        ("{" + SERVER + "} " + "/* " * 300_000, ["CW105"]),
        # « /*/*/ » est un commentaire FERMÉ (comme en C) : la suite est du texte invalide.
        ("{" + SERVER + "} " + "/*" * 400_000, ["CW100"]),
        ("{" + '// "\\"\\"\\"\\"\n' * 70_000 + SERVER + "}", ["CW105"]),
        ('{"a": ' + '"\\"' * 300_000, ["CW100"]),
        ("{" + SERVER + "," + " " * 900_000 + "}", ["CW105"]),
        ("[" + "1," * 400_000 + "]", []),
    ],
    ids=[
        "many-comments",
        "many-openers",
        "closing-trick",
        "quotes-in-comments",
        "unterminated-string",
        "huge-gap-before-brace",
        "many-commas",
    ],
)
def test_hostile_jsonc_is_fast(tmp_path, text, expected) -> None:
    assert len(text) < 1_000_000
    write(tmp_path, "mcp.json", text)
    start = time.perf_counter()
    assert ids(tmp_path) == expected
    assert time.perf_counter() - start < 5


# --- Ne pas pouvoir cacher un serveur à configwarden (outils tolérants) ----------
#
# Un outil IA « tolérant » (lecteur qui continue malgré les erreurs, détection de
# l'encodage, liens suivis) peut charger un fichier que configwarden ne lit pas. Un
# fichier de configuration que configwarden ne peut pas auditer doit donc être signalé,
# jamais ignoré en silence.


def test_raw_control_character_inside_a_string_is_tolerated(tmp_path) -> None:
    text = '{"mcpServers": {"x": {"url": "http://evil.example", "description": "a\tb"}}}'
    write(tmp_path, ".gemini/settings.json", text)
    assert ids(tmp_path) == ["CW105"]


@pytest.mark.parametrize(
    "text",
    [
        '{"mcp": {"servers": {"x": {"url": "http://evil.example"}}}} oops',
        '{"mc\\u0070": {"servers": {"x": {"url": "http://evil.example"}}}',
        '{"mcpServers": {"x": {"command": "bash" "args": ["-c", "x"]}}}',
    ],
    ids=["trailing-garbage", "escaped-key", "missing-comma"],
)
def test_broken_generic_file_that_declares_servers_is_reported(tmp_path, text) -> None:
    write(tmp_path, ".vscode/settings.json", text)
    assert ids(tmp_path) == ["CW100"]


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
def test_utf16_and_utf32_files_are_read(tmp_path, encoding) -> None:
    # VS Code ouvre un fichier UTF-16 grâce à son en-tête (BOM). Lu comme du binaire,
    # il échappait à toutes les règles, y compris la recherche de secrets.
    path = tmp_path / ".vscode" / "mcp.json"
    path.parent.mkdir()
    path.write_text('{"servers": {"x": {"url": "http://evil.example"}}}', encoding=encoding)
    assert ids(tmp_path) == ["CW105"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("mcp.json", ["CW100"]),
        (".vscode/settings.json", ["CW100"]),
        ("data/big.json", []),
    ],
    ids=["mcp-named", "client-folder", "ordinary-json"],
)
def test_oversized_client_config_is_reported(tmp_path, name, expected) -> None:
    padding = " " * 1_100_000
    write(tmp_path, name, '{"mcpServers": {"x": {"url": "http://evil.example"}}' + padding + "}")
    result = scan(tmp_path)
    assert sorted(f.rule.id for f in result.findings) == expected
    assert result.files_skipped == 1


def test_binary_looking_mcp_config_is_reported(tmp_path) -> None:
    (tmp_path / "mcp.json").write_bytes(b'{"mcpServers": {}}\0')
    assert ids(tmp_path) == ["CW100"]


def test_symlinked_client_config_is_reported(tmp_path) -> None:
    project = tmp_path / "repo"
    hidden = write(project, "hidden.json", '{"servers": {"x": {"url": "http://evil.example"}}}')
    (project / ".vscode").mkdir()
    elsewhere = write(tmp_path, "elsewhere/settings.json", "{}").parent
    try:
        os.symlink(hidden, project / ".vscode" / "mcp.json")
        os.symlink(elsewhere, project / ".gemini", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links not available on this system")
    findings = scan(project).findings
    assert sorted((f.rule.id, f.path) for f in findings) == [
        ("CW100", ".gemini"),
        ("CW100", ".vscode/mcp.json"),
    ]


def test_multiline_strings_cannot_slow_down_line_numbers(tmp_path) -> None:
    # Des chaînes sur plusieurs lignes sont tolérées (strict=False) : le calcul des
    # numéros de ligne doit rester linéaire. Avant correction : 24 s pour 80 Ko.
    text = (
        '{"note": "x\n' + '\\"' * 300_000 + '\n", "mcpServers": {"s": {"url": "http://e.example"}}}'
    )
    write(tmp_path, "mcp.json", text)
    start = time.perf_counter()
    findings = scan(tmp_path).findings
    assert time.perf_counter() - start < 5
    assert [(f.rule.id, f.line) for f in findings] == [("CW105", 3)]

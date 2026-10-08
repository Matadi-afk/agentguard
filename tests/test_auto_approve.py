"""Tests v0.3.0 (jour 3) : règle CW109 et SARIF relatif au dossier courant.

CW109 : un réglage de l'outil IA qui fait tout approuver sans demander. Dans un
dépôt, c'est ce qui transforme l'ouverture d'un projet piégé en exécution
automatique (décision du chef de projet du 8 octobre 2026, gravité haute).
Réglages relevés dans la documentation officielle de chaque outil (8 octobre 2026).
"""

import json

import pytest

from configwarden.cli import main
from configwarden.scanner import scan


def write(root, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --- CW109 : approbation globale ------------------------------------------------


@pytest.mark.parametrize(
    ("name", "text", "shown"),
    [
        (
            ".claude/settings.json",
            '{"enableAllProjectMcpServers": true}',
            "enableAllProjectMcpServers",
        ),
        (
            ".claude/settings.local.json",
            '{"permissions": {"defaultMode": "bypassPermissions"}}',
            "bypassPermissions",
        ),
        (
            ".claude/settings.json",
            '{"skipDangerousModePermissionPrompt": true}',
            "skipDangerousModePermissionPrompt",
        ),
        (
            ".vscode/settings.json",
            '{\n  // réglages\n  "chat.tools.global.autoApprove": true,\n}',
            "chat.tools.global.autoApprove",
        ),
        (".vscode/settings.json", '{"chat.tools.autoApprove": true}', "chat.tools.autoApprove"),
        (
            ".zed/settings.json",
            '{"agent": {"always_allow_tool_actions": true}}',
            "always_allow_tool_actions",
        ),
        (
            ".zed/settings.json",
            '{"agent": {"tool_permissions": {"default": "allow"}}}',
            "tool_permissions",
        ),
        ("settings.json", '{"session": {"trust_all_worktrees": true}}', "trust_all_worktrees"),
        (".cursor/permissions.json", '{"mcpAllowlist": ["github:*", "*:*"]}', "*:*"),
        (".cursor/cli.json", '{"permissions": {"allow": ["Mcp(*:*)"]}}', "Mcp(*:*)"),
        ("settings.json", '{"kiroAgent.agentAutonomy": "Autopilot"}', "Autopilot"),
    ],
    ids=[
        "claude-all-project-servers",
        "claude-bypass-permissions",
        "claude-skip-dangerous-prompt",
        "vscode-global-auto-approve",
        "vscode-legacy-auto-approve",
        "zed-always-allow",
        "zed-default-allow",
        "zed-trust-all-worktrees",
        "cursor-mcp-allowlist",
        "cursor-cli-allow",
        "kiro-autopilot",
    ],
)
def test_global_auto_approval_is_flagged(tmp_path, name, text, shown) -> None:
    write(tmp_path, name, text)
    findings = scan(tmp_path).findings
    assert [f.rule.id for f in findings] == ["CW109"]
    assert shown in findings[0].message
    assert findings[0].severity.value == "high"


@pytest.mark.parametrize(
    "text",
    [
        '{"enableAllProjectMcpServers": false}',
        '{"enableAllProjectMcpServers": "true"}',
        '{"enabledMcpjsonServers": ["github"]}',
        '{"permissions": {"defaultMode": "default"}}',
        '{"chat.tools.global.autoApprove": false}',
        '{"agent": {"tool_permissions": {"default": "confirm"}}}',
        '{"mcpAllowlist": ["github:get_issue", "github:*"]}',
        '{"permissions": {"allow": ["Mcp(github:get_issue)"]}}',
        '{"kiroAgent.agentAutonomy": "Supervised"}',
    ],
)
def test_confirmation_kept_is_fine(tmp_path, text) -> None:
    write(tmp_path, "settings.json", text)
    assert scan(tmp_path).findings == []


def test_unexpected_types_never_crash(tmp_path) -> None:
    text = json.dumps(
        {
            "agent": "not an object",
            "permissions": [1, 2],
            "mcpAllowlist": "*:*",
            "chat.tools.global.autoApprove": {"x": 1},
            "session": None,
            "kiroAgent.agentAutonomy": ["Autopilot"],
        }
    )
    write(tmp_path, "settings.json", text)
    assert scan(tmp_path).findings == []


def test_line_points_to_the_setting(tmp_path) -> None:
    write(
        tmp_path,
        ".claude/settings.json",
        '{\n  "model": "x",\n  "enableAllProjectMcpServers": true\n}',
    )
    assert [(f.rule.id, f.line) for f in scan(tmp_path).findings] == [("CW109", 3)]


def test_settings_and_servers_in_the_same_file(tmp_path) -> None:
    text = (
        '{"agent": {"always_allow_tool_actions": true},'
        ' "context_servers": {"s": {"command": "bash", "args": ["-c", "x"]}}}'
    )
    write(tmp_path, ".zed/settings.json", text)
    assert sorted(f.rule.id for f in scan(tmp_path).findings) == ["CW101", "CW109"]


def test_cw109_is_listed_with_the_rules(capsys) -> None:
    main(["rules"])
    assert "CW109" in capsys.readouterr().out


# --- SARIF : chemins relatifs au dossier courant (racine du dépôt en CI) ----------


def _sarif_location(capsys) -> dict:
    sarif = json.loads(capsys.readouterr().out)
    return sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]


def test_sarif_paths_are_relative_to_the_current_folder(tmp_path, capsys, monkeypatch) -> None:
    # En CI, la commande est lancée à la racine du dépôt : un sous-dossier analysé doit
    # donner « sub/mcp.json », sinon GitHub ne relie pas l'alerte au bon fichier.
    write(tmp_path, "sub/mcp.json", '{"mcpServers": {"s": {"url": "http://evil.example"}}}')
    monkeypatch.chdir(tmp_path)
    main(["scan", "sub", "--format", "sarif"])
    location = _sarif_location(capsys)
    assert location == {"uri": "sub/mcp.json", "uriBaseId": "%SRCROOT%"}


def test_sarif_outside_the_current_folder_stays_relative(tmp_path, capsys, monkeypatch) -> None:
    # Jamais de chemin absolu dans le rapport : il pourrait révéler un nom d'utilisateur.
    write(tmp_path, "project/mcp.json", '{"mcpServers": {"s": {"url": "http://evil.example"}}}')
    (tmp_path / "elsewhere").mkdir()
    monkeypatch.chdir(tmp_path / "elsewhere")
    main(["scan", str(tmp_path / "project"), "--format", "sarif"])
    location = _sarif_location(capsys)
    assert location == {"uri": "mcp.json"}

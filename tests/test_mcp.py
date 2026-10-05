from pathlib import Path, PurePosixPath

import pytest

from agentguard.rules import mcp
from agentguard.scanner import scan

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def rule_ids(path: Path) -> list[str]:
    return sorted(f.rule.id for f in scan(path).findings)


# --- AG101 : shell --------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [("bash", ["-c", "echo hi"]), ("/bin/sh", ["-c", "x"]), ("C:\\Windows\\cmd.exe", ["/c", "x"])],
)
def test_shell_execution_is_flagged(write_mcp, command, args) -> None:
    assert rule_ids(write_mcp({"s": {"command": command, "args": args}})) == ["AG101"]


def test_direct_binary_is_fine(write_mcp) -> None:
    assert rule_ids(write_mcp({"s": {"command": "/usr/local/bin/my-server", "args": []}})) == []


# --- AG102 : versions non figées ------------------------------------------------


@pytest.mark.parametrize(
    "package",
    ["@modelcontextprotocol/server-github", "some-server", "@scope/pkg@latest", "pkg@next"],
)
def test_unpinned_npx_package_is_flagged(write_mcp, package) -> None:
    assert rule_ids(write_mcp({"s": {"command": "npx", "args": ["-y", package]}})) == ["AG102"]


@pytest.mark.parametrize("package", ["@scope/pkg@1.2.3", "some-server@0.4.0"])
def test_pinned_npx_package_is_fine(write_mcp, package) -> None:
    assert rule_ids(write_mcp({"s": {"command": "npx", "args": ["-y", package]}})) == []


@pytest.mark.parametrize(
    ("package", "expected"), [("mcp-server==1.0", []), ("mcp-server", ["AG102"])]
)
def test_uvx_pinning(write_mcp, package, expected) -> None:
    assert rule_ids(write_mcp({"s": {"command": "uvx", "args": [package]}})) == expected


# --- AG103 : secrets dans env / headers -----------------------------------------


def test_literal_token_in_env_is_flagged_and_redacted(write_mcp) -> None:
    path = write_mcp({"s": {"command": "srv", "env": {"API_TOKEN": "my-literal-value-123"}}})
    findings = scan(path).findings
    assert [f.rule.id for f in findings] == ["AG103"]
    assert "my-literal-value-123" not in findings[0].message


@pytest.mark.parametrize(
    "value", ["${API_TOKEN}", "${env:API_TOKEN}", "$API_TOKEN", "${input:token}", "Bearer ${TOKEN}"]
)
def test_env_references_are_fine(write_mcp, value) -> None:
    path = write_mcp({"s": {"command": "srv", "env": {"API_TOKEN": value}}})
    assert rule_ids(path) == []


def test_non_sensitive_env_is_ignored(write_mcp) -> None:
    path = write_mcp({"s": {"command": "srv", "env": {"LOG_LEVEL": "debug"}}})
    assert rule_ids(path) == []


# --- AG104 : accès disque trop large --------------------------------------------


@pytest.mark.parametrize("folder", ["/", "~", "~/", "C:\\", "${userHome}"])
def test_broad_filesystem_access_is_flagged(write_mcp, folder) -> None:
    args = ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", folder]
    assert rule_ids(write_mcp({"fs": {"command": "npx", "args": args}})) == ["AG104"]


def test_project_folder_access_is_fine(write_mcp) -> None:
    args = ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "./data"]
    assert rule_ids(write_mcp({"fs": {"command": "npx", "args": args}})) == []


# --- AG105 : HTTP non chiffré ---------------------------------------------------


def test_plain_http_remote_is_flagged(write_mcp) -> None:
    assert rule_ids(write_mcp({"r": {"url": "http://mcp.example.com/sse"}})) == ["AG105"]


@pytest.mark.parametrize("url", ["https://mcp.example.com", "http://localhost:3000/mcp"])
def test_https_and_localhost_are_fine(write_mcp, url) -> None:
    assert rule_ids(write_mcp({"r": {"url": url}})) == []


# --- Formats et fichiers --------------------------------------------------------


def test_vscode_servers_format_is_supported(write_mcp) -> None:
    path = write_mcp({"r": {"url": "http://evil.example"}}, name=".vscode/mcp.json", key="servers")
    assert rule_ids(path) == ["AG105"]


def test_invalid_json_is_reported(tmp_path) -> None:
    (tmp_path / "mcp.json").write_text("{ not json", encoding="utf-8")
    assert rule_ids(tmp_path) == ["AG100"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("mcp.json", True),
        (".mcp.json", True),
        ("claude_desktop_config.json", True),
        ("team.mcp.json", True),
        ("package.json", False),
    ],
)
def test_mcp_file_detection(name, expected) -> None:
    assert mcp.is_mcp_config(PurePosixPath(name)) is expected


# --- Exemples fournis avec le projet --------------------------------------------


def test_vulnerable_example_triggers_every_mcp_rule() -> None:
    ids = set(rule_ids(EXAMPLES / "vulnerable-mcp"))
    assert {"AG101", "AG102", "AG103", "AG104", "AG105"} <= ids


def test_safe_example_is_clean() -> None:
    assert rule_ids(EXAMPLES / "safe-mcp") == []

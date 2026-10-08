import json
import os

import pytest

from configwarden.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from configwarden.scanner import scan
from tests.conftest import fake_secret


@pytest.fixture
def leaky_project(tmp_path):
    (tmp_path / "app.py").write_text("token = '" + fake_secret("ghp_", 36) + "'\n")
    (tmp_path / "README.md").write_text("Nothing to see\n")
    return tmp_path


def test_ignored_directories_are_skipped(tmp_path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text(fake_secret("ghp_", 36))
    assert scan(tmp_path).findings == []


def test_exclude_glob(leaky_project) -> None:
    assert scan(leaky_project, excludes=["*.py"]).findings == []


def test_binary_and_large_files_are_skipped(tmp_path) -> None:
    (tmp_path / "blob.bin").write_bytes(b"\0" + fake_secret("ghp_", 36).encode())
    result = scan(tmp_path)
    assert result.findings == [] and result.files_skipped == 1


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unsupported")
def test_symlinks_are_not_followed(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(fake_secret("ghp_", 36))
    project = tmp_path / "project"
    project.mkdir()
    try:
        (project / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("cannot create symlink on this system")
    assert scan(project).findings == []


def test_cli_exit_codes(leaky_project, tmp_path, capsys) -> None:
    assert main(["scan", str(leaky_project)]) == EXIT_FINDINGS
    assert main(["scan", str(leaky_project), "--exclude", "*.py"]) == EXIT_OK
    assert main(["scan", str(tmp_path / "missing")]) == EXIT_ERROR


def test_fail_on_threshold(tmp_path) -> None:
    (tmp_path / "mcp.json").write_text('{"mcpServers": {"s": {"command": "npx", "args": ["pkg"]}}}')
    assert main(["scan", str(tmp_path), "--fail-on", "high"]) == EXIT_OK  # CW102 = medium
    assert main(["scan", str(tmp_path), "--fail-on", "medium"]) == EXIT_FINDINGS


def test_json_output_never_contains_the_secret(leaky_project, capsys) -> None:
    secret = fake_secret("ghp_", 36)
    main(["scan", str(leaky_project), "--format", "json"])
    out = capsys.readouterr().out
    assert secret not in out
    assert json.loads(out)["findings"][0]["rule"]["id"] == "CW001"


def test_sarif_output_is_valid(leaky_project, tmp_path) -> None:
    report = tmp_path / "out.sarif"
    main(["scan", str(leaky_project), "--format", "sarif", "--output", str(report)])
    sarif = json.loads(report.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "CW001"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert fake_secret("ghp_", 36) not in report.read_text(encoding="utf-8")


def test_rules_command(capsys) -> None:
    assert main(["rules"]) == EXIT_OK
    assert "CW001" in capsys.readouterr().out

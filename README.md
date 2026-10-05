# agentguard

**Security scanner for AI agent configurations.** Finds hardcoded secrets, dangerous MCP server setups and supply-chain risks before they reach production.

[![CI](https://github.com/Matadi-afk/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Matadi-afk/agentguard/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

AI agents (Claude, Cursor, VS Code Copilot…) are increasingly wired to tools through the **Model Context Protocol (MCP)**. One bad config line can hand an agent, or anyone who hijacks it through prompt injection, a shell on your machine or your whole home directory. `agentguard` catches these mistakes in seconds.

- **Zero runtime dependencies**: nothing extra to trust.
- **Never prints a secret in full**: reports are safe to share in CI logs.
- **SARIF output**: results show up natively in GitHub Code Scanning and other security dashboards.

## Quick start

```bash
pip install agentguard        # coming soon on PyPI; for now: pip install .
agentguard scan .
```

```text
[CRITICAL] AG001 Hardcoded secret
    app/config.py:12  GitHub token found: ghp_****…(40 chars)
    Fix: Revoke the key immediately in the provider dashboard…

[HIGH] AG101 MCP server runs through a shell
    mcp.json:16  Server 'helper' executes commands through 'bash'.
```

## Rules

| ID | Severity | What it detects |
|----|----------|-----------------|
| AG001 | critical | API keys and tokens written in clear (Anthropic, OpenAI, GitHub, AWS, Google, Hugging Face, Slack, Stripe, private keys) |
| AG100 | low | MCP config that is not valid JSON (cannot be audited) |
| AG101 | high | MCP server launched through `bash -c`, `cmd /c`, PowerShell… |
| AG102 | medium | `npx` / `uvx` package without a pinned version |
| AG103 | high | Secret written literally in an MCP server's `env` or `headers` |
| AG104 | high | Filesystem server exposed to `/`, `~` or `C:\` |
| AG105 | high | Remote MCP server reached over plain `http://` |

Run `agentguard rules` to list them from the CLI.

## Usage

```bash
agentguard scan PATH [--format text|json|sarif] [--output FILE]
                     [--fail-on low|medium|high|critical] [--exclude GLOB]...
```

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` usage error.

### GitHub Actions

```yaml
- run: pip install agentguard
- run: agentguard scan . --format sarif --output agentguard.sarif
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: agentguard.sarif
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
pytest
```

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Apache-2.0

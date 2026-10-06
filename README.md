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

Requires Python 3.10+. The package is not on PyPI yet: install a tagged release from GitHub.

```bash
pip install "git+https://github.com/Matadi-afk/agentguard@v0.2.0"
agentguard scan .
```

### Try it on the bundled example

```bash
git clone https://github.com/Matadi-afk/agentguard
cd agentguard
pip install .
agentguard scan examples/vulnerable-mcp   # 10 findings
agentguard scan examples/safe-mcp         # the fixed version: no issues
```

```text
[HIGH] AG106 MCP server container escapes isolation
    mcp.json:25  Server 'sandbox' runs a container with a mount of '/var/run/docker.sock'.
    Fix: Remove --privileged, host namespaces and mounts of '/', the home directory or the Docker socket. ...

[HIGH] AG101 MCP server runs through a shell
    mcp.json:15  Server 'helper' executes commands through 'bash'.
    Fix: Call the server binary directly instead of `bash -c` / `cmd /c`. ...

Scanned 1 file(s), skipped 0. 10 finding(s): 0 critical, 8 high, 2 medium, 0 low.
```

Every value in `examples/` is a fake placeholder.

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
| AG106 | high | Docker/Podman server with `--privileged`, host namespaces, `/` or Docker socket mounts |
| AG107 | high | Package installed from git or a URL instead of the npm / PyPI registry |
| AG108 | medium | Tools auto-approved (`alwaysAllow`, `autoApprove`, `trust: true`): no human confirmation |

Run `agentguard rules` to list them from the CLI.

## Usage

```bash
agentguard scan PATH [--format text|json|sarif] [--output FILE]
                     [--fail-on low|medium|high|critical] [--exclude GLOB]...
```

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` usage error.

### GitHub Actions

```yaml
jobs:
  agentguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # needed to upload SARIF results
    steps:
      - uses: actions/checkout@v4   # pin actions to a commit SHA in production
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install "git+https://github.com/Matadi-afk/agentguard@v0.2.0"
      - run: agentguard scan . --format sarif --output agentguard.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: agentguard.sarif
```

Results then appear in the repository's **Security → Code scanning** tab.

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
pytest
```

See [CHANGELOG.md](CHANGELOG.md) for release notes and [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Apache-2.0

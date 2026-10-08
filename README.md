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
pip install "git+https://github.com/Matadi-afk/agentguard@v0.2.2"
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
| AG100 | medium | MCP config that cannot be parsed (some clients still run the servers they can read from a broken file) |
| AG101 | high | Shell running a script (`bash -c`, `pwsh -Command`), `cmd /c` with a command line or special characters, inline code (`node -e`, `python -c`) |
| AG102 | medium | `npx` / `uvx` package without an exact version (`^1.0`, `@beta`, `>=1` are not pinned) |
| AG103 | high | Secret written literally in an MCP server's `env` or `headers`, including passwords inside URLs |
| AG104 | high | Filesystem server exposed to `/`, a whole drive or a whole home directory |
| AG105 | high | Remote MCP server reached over plain `http://` |
| AG106 | high | Docker/Podman server with `--privileged`, host namespaces, or mounts of `/`, the home directory, `.ssh`/`.aws`… or the Docker socket |
| AG107 | high | Package installed from git, a URL or a GitHub shorthand instead of the npm / PyPI registry |
| AG108 | medium | Tools auto-approved (`alwaysAllow`, `autoApprove`, `trust: true`): no human confirmation |

Run `agentguard rules` to list them from the CLI.

## Supported configuration files

agentguard reads every `.json` / `.jsonc` file (comments and trailing commas allowed) and looks for MCP servers wherever each AI client keeps them:

| Client | Where the servers live |
|---|---|
| Claude Desktop, Cursor, Windsurf, Cline, Roo Code, Kiro, Amazon Q, GitHub Copilot CLI | `mcpServers` |
| Claude Code | `.mcp.json`, and `~/.claude.json` (user and per-project servers) |
| Gemini CLI | `mcpServers` in `.gemini/settings.json` and extensions (`url`, `httpUrl`) |
| VS Code | `servers` in `.vscode/mcp.json`, `mcp.servers` in settings, `devcontainer.json` customizations |
| Zed | `context_servers` in `settings.json` |

Other JSON files are only reported when they contain MCP servers. YAML (Continue) and TOML (Codex CLI) configurations are not supported yet.

Wrapped commands are unwrapped before being checked: `cmd /c npx …`, `wsl …`, `env VAR=1 …`, `sudo …` and `bash -c "…"` are all analysed for the program they really start.

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
      - run: pip install "git+https://github.com/Matadi-afk/agentguard@v0.2.2"
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

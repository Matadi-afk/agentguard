# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-10-07

### Security
Three issues found during an internal security review of agentguard itself. They could only be triggered by a scanned file crafted by an attacker. No user report, no known exploitation.
- **Credentials leaked in reports**: AG107 and AG102 copied package URLs verbatim, so `git+https://user:token@host/…` printed the token in clear in text, JSON and SARIF output. Credentials embedded in URLs are now masked (`https://****@host/…`).
- **Output injection**: server names and file paths were printed as-is. Newlines could forge GitHub Actions workflow commands (lines starting with `::`) and ANSI or bidirectional control characters could hide or rewrite terminal output. All control, line-separator and bidi characters in findings are now escaped (`\n`, `\x1b`, `\u202e`…), whatever the output format.
- **Denial of service**: a deeply nested JSON file (`[[[[…]]]]`) crashed the whole scan with a `RecursionError`. It is now reported as AG100 (unreadable configuration) and the rest of the project is still scanned.

### Added
- `tests/test_hardening.py`: regression tests that replay each attack, plus a permanent check that no invisible or bidirectional characters exist in the project's own source code.

## [0.2.0] - 2026-10-06

### Added
- **AG106** (high): container-based MCP servers (`docker`, `podman`, `nerdctl` `run`) that break isolation: `--privileged`, host namespaces (`--network host`, `--pid host`…), mounts of `/`, the home directory, `C:\`, `/etc`, `/root`, `/var/run` or the Docker socket, dangerous `--cap-add`, `--security-opt …=unconfined`.
- **AG107** (high): MCP packages installed from git or a URL (`github:`, `git+https://`, `https://…tgz`, `uvx --from git+…`) instead of the npm / PyPI registry.
- **AG108** (medium): tools that run without user confirmation (`alwaysAllow`, `autoApprove`, `trust: true`).
- Demo entries for the new rules in `examples/vulnerable-mcp` and their fixed versions in `examples/safe-mcp`.

### Changed
- AG102 (unpinned package) is no longer reported when AG107 already flags the same package, to avoid duplicate alerts.

## [0.1.0] - 2026-10-05

### Added
- First release: AG001 (hardcoded secrets) and AG100–AG105 (MCP configuration checks).
- Text, JSON and SARIF 2.1.0 reports; exit codes for CI.
- Zero runtime dependencies; secrets are always redacted in reports.

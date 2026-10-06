# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

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

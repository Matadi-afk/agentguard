# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.2] - 2026-10-07

### Security
Found by an independent review of 0.2.1, then re-checked by two further bypass attempts on the fixes. All issues require a scanned file or repository crafted by an attacker. No user report, no known exploitation.
- **Credentials still leaked in reports**: URLs with several `@`, a `/`, `?`, `#`, quote or space in the password, a token in the query string (`?token=…`) or in the path of a private registry, and npm shorthands such as `github:user:token@…` were not fully masked. AG107 now shows only the origin of the URL (`https://host/…`).
- **Crash on a malformed URL**: an invalid `url` (e.g. `http://[broken`) stopped the whole scan, and Python's error message could echo the password and raw escape codes. It is now reported as AG105 without echoing the URL, and an unexpected error in one server no longer hides the findings of the others.
- **Report crash on invalid Unicode**: a lone surrogate in a server name or file name made every output format fail and left an empty SARIF file. Surrogates and every Unicode default-ignorable character (zero-width, BOM, tag characters, variation selectors…), which can hide text from humans while an AI reading the report still sees it, are now escaped.
- **Report written through a symbolic link**: `--output` followed a symlink planted in the scanned repository (`agentguard.sarif -> ../file`, or a symlinked folder), which could overwrite another file in CI. agentguard now refuses to write through a symlink or to an output path containing `..`.
- **Denial of service**: line numbers were computed in quadratic time; a crafted file of a few hundred KB blocked the scan for minutes. A FIFO in the scanned tree blocked it forever. Both are fixed (single pass, regular files only).

### Changed
- Short secrets (under 16 characters) are fully masked (`****`) instead of showing their first 4 characters.
- AG103 no longer treats `PATH` as a secret (`PAT` must be a whole word) and now detects `*_PASS` keys.
- AG102/AG107 know which `npx` and `uvx` options take a value (`--registry`, `--index-url`, `uvx -p 3.12`…), which were mistaken for the package; `uvx --with git+…` is now flagged.
- Files starting with a UTF-8 BOM are now analysed instead of being reported as invalid JSON.
- Line numbers count only real line breaks (`\n`), as editors and GitHub do; SARIF URIs are percent-encoded.
- Unreadable folders are counted as skipped, and the text report says when some files could not be analysed.

## [0.2.1] - 2026-10-07

### Security
Three issues found during an internal security review of agentguard itself. They could only be triggered by a scanned file crafted by an attacker. No user report, no known exploitation.
- **Credentials leaked in reports**: AG107 and AG102 copied package URLs verbatim, so `git+https://user:token@host/…` printed the token in clear in text, JSON and SARIF output. Credentials embedded in URLs are now masked (`https://****@host/…`).
- **Output injection**: server names and file paths were printed as-is. Newlines could forge GitHub Actions workflow commands (lines starting with `::`) and ANSI or bidirectional control characters could hide or rewrite terminal output. All control, line-separator and bidi characters in findings are now escaped (`\n`, `\x1b`, `\u202e`…), whatever the output format.
- **Denial of service**: a deeply nested JSON file (`[[[[…]]]]`) crashed the whole scan with a `RecursionError`. It is now reported as AG100 (unreadable configuration) and the rest of the project is still scanned.

### Added
- `tests/test_hardening.py`: regression tests that replay each attack, plus a permanent check that no invisible or bidirectional characters exist in the project's own source code.

### Changed
- Development: pre-commit hooks are pinned to commit SHAs instead of tags.

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

[Unreleased]: https://github.com/Matadi-afk/agentguard/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/Matadi-afk/agentguard/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Matadi-afk/agentguard/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Matadi-afk/agentguard/releases/tag/v0.2.0

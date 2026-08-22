# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-22

### Added
- Initial release.
- Checks: `dns`, `ping`, `tcp`, `tls` (expiry), `http`, `trace` (opt-in).
- Human-readable table and `--json` output.
- Meaningful exit codes for use in CI and monitoring.
- Zero runtime dependencies (standard library only).

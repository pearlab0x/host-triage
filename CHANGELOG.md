# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-23

### Added
- Multiple targets in one run, passed as arguments, via `-f/--file` (repeatable),
  or on stdin (`-`); files support `#` comments and blank lines.
- Concurrent execution across targets with `-j/--jobs` (auto by default);
  results are always reported in input order.
- Per-target output sections plus a summary footer, and a batch JSON shape
  (`{ok, failures, targets: [...]}`) when more than one target is checked.
- `-p/--port` now applies to every target.

### Changed
- A single, unparseable target no longer aborts the run; it reports a failing
  `target` check instead.
- Exit code reflects the worst result across all targets.

## [0.1.0] - 2026-08-22

### Added
- Initial release.
- Checks: `dns`, `ping`, `tcp`, `tls` (expiry), `http`, `trace` (opt-in).
- Human-readable table and `--json` output.
- Meaningful exit codes for use in CI and monitoring.
- Zero runtime dependencies (standard library only).

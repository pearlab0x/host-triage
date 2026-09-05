# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-09-06

### Added

- `--fail-on {fail,warn}`: choose the severity that exits non-zero. The default
  (`fail`) is unchanged; `--fail-on warn` also gates on warnings, so an
  expiring certificate or a `4xx` can break a build instead of passing quietly.
  Skipped checks never trip the gate.
- `headers` check (opt-in via `--headers` or `-c headers`): audits the HTTP
  response for HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, and
  `Referrer-Policy`. Reports which are missing, and flags headers that are
  present but ineffective (HSTS `max-age` below six months, a
  `X-Content-Type-Options` that isn't `nosniff`). HSTS is not counted over
  plain `http://`, and error responses are still audited.
- `dmarc` check (opt-in via `--dmarc` or `-c dmarc`): resolves
  `_dmarc.<domain>` and parses the policy tags (`p`, `sp`, `rua`, `ruf`,
  `pct`, …). Warns on a missing record, more than one record, a record with no
  policy, `p=none`, or a `pct` below 100, since none of those enforce anything.
  Requires `dig` on PATH; skips gracefully without it.
- `-w/--watch [SECONDS]`: re-run continuously, redrawing in place (default 5s,
  ctrl-c to stop). With `--json` or when piped, it streams one document per
  cycle instead of clearing the screen. The exit code is that of the last pass.

### Changed

- The failure count in the output header and in batch JSON now follows
  `--fail-on`, so what's printed always matches the exit code.

### CI/CD

- Actions are pinned to commit SHAs, with Dependabot configured to move both
  the pins and the dev toolchain weekly.
- CI caches pip downloads, enforces an 80% coverage floor, and gained a `build`
  job that builds the sdist/wheel, runs `twine check --strict`, and smoke-tests
  the installed wheel.
- New tag-driven release workflow: verifies the tag matches the packaged
  version, publishes to PyPI via Trusted Publishing (no stored token), and cuts
  a GitHub Release with notes taken from this changelog.

## [0.3.0] - 2026-08-23

### Added

- `spf` check (opt-in via `--spf` or `-c spf`): looks up the domain's TXT
  records, finds the `v=spf1` record, and reports its parsed mechanisms
  (`include:`, `ip4:`, `ip6:`, `a`, `mx`, `exists:`, `redirect=`, and the
  `all` qualifier) in the summary and JSON details. Useful for surfacing the
  real origins behind a CDN. Requires `dig` on PATH; skips gracefully without
  it, warns when no SPF record exists or when more than one is present.

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

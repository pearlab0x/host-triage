# host-triage

[![PyPI](https://img.shields.io/pypi/v/host-triage)](https://pypi.org/project/host-triage/)
[![CI](https://github.com/pearlab0x/host-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/pearlab0x/host-triage/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

One command to answer _"is this host actually up, and if not, where does it break?"_

`host-triage` runs the checks you'd otherwise run by hand - DNS resolution,
ping, a TCP connect, TLS certificate expiry, and an HTTP request - against one
or more targets (concurrently), then prints a compact table (or JSON) and exits
with a code you can gate on. Opt-in checks cover traceroute, SPF, DMARC, and
HTTP security headers.

```console
$ host-triage api.example.com
host-triage  api.example.com  (1 check(s) failed)

  OK    dns   resolved 2 addresses (93.184.216.34, 2606:2800:220:1::1)   11 ms
  OK    ping  reachable, avg 9.5 ms                                      42 ms
  OK    tcp   connected to 93.184.216.34:443                             41 ms
  WARN  tls   certificate valid, expires in 9 day(s) (2026-08-31)        44 ms
  FAIL  http  503 Service Unavailable                                   120 ms

$ echo $?
1
```

## Why

When something is unreachable, the first five minutes are always the same
sequence of `dig`, `ping`, `nc -zv`, `curl -I`, and `openssl s_client` to find
the layer that's broken. This collapses that into one call with consistent
output.

- **Zero runtime dependencies.** Pure standard library; runs anywhere Python 3.11+ does.
- **Scriptable.** `--json` for machines, exit codes for pipelines.
- **Layered.** Each check is independent, so you see exactly which layer fails.

## Install

```bash
# with pipx (recommended for a CLI)
pipx install host-triage

# or with pip
pip install host-triage

# latest unreleased code
pipx install git+https://github.com/pearlab0x/host-triage

# or from a clone
git clone https://github.com/pearlab0x/host-triage
cd host-triage
pip install .
```

No install needed to try it - `python -m host_triage example.com` works from a clone.

## Usage

```bash
host-triage example.com                     # default checks: dns, ping, tcp, tls, http
host-triage https://api.example.com:8443    # scheme and port taken from the URL
host-triage db.internal -c dns,tcp -p 5432  # only some checks, explicit port
host-triage example.com --trace             # add traceroute (slow, off by default)
host-triage example.com -a                  # every check
host-triage example.com --json | jq .       # machine-readable (needs jq)
host-triage example.com -t 2                 # 2-second per-check timeout
host-triage example.com --spf                # also resolve the SPF record
host-triage example.com --dmarc              # also resolve the DMARC record
host-triage example.com --headers            # also audit HTTP security headers
host-triage example.com --fail-on warn       # exit non-zero on warnings too
host-triage example.com --watch 10           # re-check every 10s until ctrl-c
host-triage example.com -c spf --json | jq .details   # just the SPF, structured (needs jq)
```

### Failing on warnings

By default only a `FAIL` breaks the run, so a certificate with 9 days left
exits `0`. `--fail-on warn` moves the gate down a level, which is what you
usually want in CI:

```console
$ host-triage example.com --fail-on warn
host-triage  example.com  (1 check(s) at or above warn)

  WARN  tls  certificate valid, expires in 9 day(s) (2026-09-14)  44 ms

$ echo $?
1
```

Skipped checks never trip the gate, and the count in the header always matches
the exit code.

### Watching a host

`--watch` re-runs the same checks until you stop it - useful while waiting for
a deploy to come back or a DNS change to propagate:

```bash
host-triage api.example.com --watch        # every 5s, redrawn in place
host-triage api.example.com --watch 30     # every 30s
host-triage api.example.com -w 10 --json   # one JSON document per cycle
```

On a terminal it clears and redraws; piped or with `--json` it just appends,
so the output stays usable downstream. The exit code is that of the last pass.

### Multiple targets

Pass several targets at once and they're checked in parallel:

```bash
host-triage a.example.com b.example.com api.example.com:8443
host-triage -f hosts.txt                      # one target per line ('#' comments ok)
cat hosts.txt | host-triage                    # or piped on stdin
host-triage -f prod.txt -f staging.txt -j 20   # multiple files, 20 workers
```

Results are always printed in the order the targets were given, regardless of
which finishes first, and the run exits non-zero if _any_ target has a failure.
A single unparseable target reports a failing `target` check instead of
aborting the whole batch. Worker count is chosen automatically; override it with
`-j/--jobs`.

### Targets

Accepts `host`, `host:port`, or a full URL, including bracketed IPv6:

```
example.com            example.com:8443       https://example.com/health
[2606:4700:4700::1111] 1.1.1.1:853            http://api.internal:8080
```

## Checks

| Check     | What it verifies                                       | Notes                                       |
| --------- | ------------------------------------------------------ | ------------------------------------------- |
| `dns`     | Hostname resolves to one or more A/AAAA records        |                                             |
| `ping`    | ICMP reachability and average RTT                      | Shells out to the system `ping`             |
| `tcp`     | A TCP connection to the port can be established        | Reports the peer IP and connect latency     |
| `tls`     | Certificate is valid and not expiring soon             | `WARN` within `--tls-warn-days` (21)        |
| `http`    | An HTTP(S) request returns a non-5xx status            | Follows redirects; `4xx` warns, `5xx` fails |
| `headers` | Response carries the standard security headers         | Opt-in via `--headers`                      |
| `trace`   | Traceroute hop count to the host                       | Opt-in via `--trace`; can be slow           |
| `spf`     | Looks up the domain's SPF (TXT) record and its origins | Opt-in via `--spf`; needs `dig` on PATH     |
| `dmarc`   | Looks up `_dmarc.<domain>` and reads the policy        | Opt-in via `--dmarc`; needs `dig` on PATH   |

Statuses are `OK`, `WARN`, `FAIL`, and `--` (skipped, e.g. `tls` on a plain
`http://` target).

### Security headers

`headers` looks for HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, and
`Referrer-Policy`, and warns on anything missing. It also flags headers that
are present but do not deliver what they promise - an HSTS `max-age` under six
months, or an `X-Content-Type-Options` that isn't `nosniff`. HSTS is not
counted over plain `http://`, where it means nothing, and an error response
(say a `403`) is still audited rather than discarded.

```console
$ host-triage example.com -c headers
  WARN  headers  3 of 5 security header(s) present (missing: CSP, HSTS)
```

### DMARC

`dmarc` resolves `_dmarc.<domain>` and parses the policy tags. Because the
point of the check is whether the domain is actually protected, a record that
enforces nothing is a warning: no record at all, more than one, no `p=` tag,
`p=none`, or a `pct` below 100.

```console
$ host-triage example.com -c dmarc
  OK    dmarc  DMARC: policy p=reject, sp=reject, 1 rua
```

## JSON output

```console
$ host-triage example.com -c dns,tls --json
{
  "target": "example.com",
  "ok": true,
  "worst": "ok",
  "checks": [
    {
      "name": "dns",
      "status": "ok",
      "summary": "resolved 1 address (93.184.216.34)",
      "details": { "addresses": ["93.184.216.34"] },
      "duration_ms": 11.4
    },
    {
      "name": "tls",
      "status": "ok",
      "summary": "certificate valid, expires in 61 day(s) (2026-10-22)",
      "details": { "days_left": 61, "not_after": "2026-10-22", "issuer": "Let's Encrypt" },
      "duration_ms": 44.1
    }
  ]
}
```

For a single target the JSON is the flat object shown above. For **multiple**
targets it's wrapped so you can gate on the batch as a whole:

```json
{
  "ok": false,
  "failures": 1,
  "targets": [ { "target": "a.example.com", "ok": true,  "checks": [ ... ] },
               { "target": "b.example.com", "ok": false, "checks": [ ... ] } ]
}
```

## Exit codes

| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| `0`  | Nothing reached the threshold on any target               |
| `1`  | One or more checks reached it on one or more targets      |
| `2`  | Usage error                                               |
| `3`  | Unexpected error                                          |

The threshold is `fail` by default, so a warning (e.g. a cert with 9 days left)
does **not** break the run - wire it into CI and only fail on a real outage:

```yaml
- name: Smoke-test production
  run: host-triage https://example.com/health --json
```

Or tighten it so an expiring certificate breaks the build *before* it expires:

```yaml
- name: Certificate and header posture
  run: host-triage https://example.com --headers --fail-on warn
```

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
pytest --cov=host_triage
```

The suite mocks all network I/O, so it's fast and runs offline. CI checks lint,
formatting, and types, runs the tests on Linux, macOS, and Windows across
Python 3.11–3.13 against an 80% coverage floor, then builds the sdist and wheel
and smoke-tests the installed package. Actions are pinned to commit SHAs and
kept current by Dependabot.

### Releasing

Releases are tag-driven. Bump the version in `pyproject.toml` and
`src/host_triage/__init__.py`, add the `CHANGELOG.md` section, then:

```bash
git tag v0.4.0 && git push origin v0.4.0
```

`release.yml` verifies the tag matches the packaged version, publishes to PyPI
via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (no token
stored in the repo), and cuts a GitHub Release with notes from the changelog.
The PyPI project must have this repo, `release.yml`, and the `pypi`
environment registered as a trusted publisher before the first run.

## Design notes

- **No third-party runtime deps** keeps install trivial and the supply chain small.
- **Classification lives in pure helpers** (`classify_http_status`,
  `classify_cert_days`, `parse_ping_rtt`, …) so the interesting logic is unit-tested
  without sockets.
- **`ping`/`traceroute` shell out** to the system binaries rather than opening raw
  ICMP sockets, which would require elevated privileges.

## License

MIT - see [LICENSE](LICENSE).

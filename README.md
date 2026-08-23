# host-triage

[![CI](https://github.com/pearlab0x/host-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/pearlab0x/host-triage/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

One command to answer _"is this host actually up, and if not, where does it break?"_

`host-triage` runs the checks you'd otherwise run by hand - DNS resolution,
ping, a TCP connect, TLS certificate expiry, and an HTTP request - against one
or more targets (concurrently), then prints a compact table (or JSON) and exits
with a code you can gate on.

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
host-triage example.com -c spf --json | jq .details   # just the SPF, structured (needs jq)
```

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

| Check   | What it verifies                                       | Notes                                       |
| ------- | ------------------------------------------------------ | ------------------------------------------- |
| `dns`   | Hostname resolves to one or more A/AAAA records        |                                             |
| `ping`  | ICMP reachability and average RTT                      | Shells out to the system `ping`             |
| `tcp`   | A TCP connection to the port can be established        | Reports the peer IP and connect latency     |
| `tls`   | Certificate is valid and not expiring soon             | `WARN` within `--tls-warn-days` (21)        |
| `http`  | An HTTP(S) request returns a non-5xx status            | Follows redirects; `4xx` warns, `5xx` fails |
| `trace` | Traceroute hop count to the host                       | Opt-in via `--trace`; can be slow           |
| `spf`   | Looks up the domain's SPF (TXT) record and its origins | Opt-in via `--spf`; needs `dig` on PATH     |

Statuses are `OK`, `WARN`, `FAIL`, and `--` (skipped, e.g. `tls` on a plain
`http://` target).

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

| Code | Meaning                                          |
| ---- | ------------------------------------------------ |
| `0`  | All checks clear on every target (warnings pass) |
| `1`  | One or more checks failed on one or more targets |
| `2`  | Usage error                                      |
| `3`  | Unexpected error                                 |

Because a warning (e.g. a cert with 9 days left) does **not** fail the run, you
can wire it into CI and only break the build on a real outage:

```yaml
- name: Smoke-test production
  run: host-triage https://example.com/health --json
```

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
pytest --cov=host_triage
```

The suite mocks all network I/O, so it's fast and runs offline. CI checks lint,
formatting, and types, then runs the tests on Linux, macOS, and Windows across
Python 3.11–3.13.

## Design notes

- **No third-party runtime deps** keeps install trivial and the supply chain small.
- **Classification lives in pure helpers** (`classify_http_status`,
  `classify_cert_days`, `parse_ping_rtt`, …) so the interesting logic is unit-tested
  without sockets.
- **`ping`/`traceroute` shell out** to the system binaries rather than opening raw
  ICMP sockets, which would require elevated privileges.

## License

MIT - see [LICENSE](LICENSE).

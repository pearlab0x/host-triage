"""Command-line interface for host-triage."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .checks import DEFAULT_CHECKS, REGISTRY, CheckConfig, resolve_checks
from .render import render_json_multi, render_text_multi
from .runner import auto_jobs, run_many
from .sources import gather_targets

EXIT_OK = 0
EXIT_FAILURES = 1
EXIT_USAGE = 2
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="host-triage",
        description=(
            "Connectivity triage (DNS, ping, TCP, TLS-expiry, HTTP) for one or more targets."
        ),
        epilog="Exit codes: 0 all clear, 1 one or more checks failed, "
        "2 usage error, 3 unexpected error.",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="one or more hosts, host:port, or URLs (use '-' to read from stdin)",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        metavar="FILE",
        help=(
            "read targets from FILE (one per line, '#' comments allowed, '-' for stdin); repeatable"
        ),
    )
    parser.add_argument(
        "-c",
        "--checks",
        default=",".join(DEFAULT_CHECKS),
        help=f"comma-separated checks to run (default: {','.join(DEFAULT_CHECKS)}; "
        f"available: {','.join(REGISTRY)})",
    )
    parser.add_argument(
        "--trace", action="store_true", help="also run traceroute (slow; off by default)"
    )
    parser.add_argument("-a", "--all", action="store_true", help="run every available check")
    parser.add_argument("-p", "--port", type=int, help="override the port for every target")
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=0,
        help="parallel workers when checking multiple targets (default: auto)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=5.0, help="per-check timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "--tls-warn-days",
        type=int,
        default=21,
        help="warn when a certificate expires within this many days (default: 21)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _use_color(args: argparse.Namespace) -> bool:
    if args.no_color or args.json or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _select_checks(args: argparse.Namespace) -> list[str]:
    if args.all:
        return list(REGISTRY)
    names = [c.strip() for c in args.checks.split(",") if c.strip()]
    if args.trace and "trace" not in names:
        names.append("trace")
    return resolve_checks(names)


def _resolve_targets(args: argparse.Namespace) -> list[str]:
    positionals = [t for t in args.targets if t != "-"]
    read_stdin = "-" in args.targets

    file_texts: list[str] = []
    for path in args.file or []:
        if path == "-":
            read_stdin = True
        else:
            file_texts.append(Path(path).read_text(encoding="utf-8"))

    # With nothing on the command line and input piped in, read stdin implicitly.
    if not positionals and not args.file and not sys.stdin.isatty():
        read_stdin = True

    stdin_text = sys.stdin.read() if read_stdin else None
    return gather_targets(positionals, file_texts, stdin_text)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        check_names = _select_checks(args)
        targets = _resolve_targets(args)
    except ValueError as exc:
        parser.error(str(exc))
    except OSError as exc:
        parser.error(f"could not read targets file: {exc}")

    if not targets:
        parser.error("no targets given (pass them as arguments, via -f FILE, or on stdin)")

    cfg = CheckConfig(timeout=args.timeout, tls_warn_days=args.tls_warn_days)
    jobs = auto_jobs(len(targets), args.jobs)
    reports = run_many(targets, check_names, cfg, jobs=jobs, port=args.port)

    if args.json:
        print(render_json_multi(reports))
    else:
        print(render_text_multi(reports, color=_use_color(args)))

    return EXIT_OK if all(r.ok for r in reports) else EXIT_FAILURES


if __name__ == "__main__":
    sys.exit(main())

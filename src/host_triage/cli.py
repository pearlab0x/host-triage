"""Command-line interface for host-triage."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .checks import DEFAULT_CHECKS, REGISTRY, CheckConfig, resolve_checks
from .models import Report
from .render import render_json, render_text
from .target import Target, parse_target

EXIT_OK = 0
EXIT_FAILURES = 1
EXIT_USAGE = 2
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="host-triage",
        description="One-shot connectivity triage for a host or service.",
        epilog="Exit codes: 0 all clear, 1 one or more checks failed, "
        "2 usage error, 3 unexpected error.",
    )
    parser.add_argument("target", help="host, host:port, or URL (e.g. example.com, https://api:8443)")
    parser.add_argument(
        "-c", "--checks",
        default=",".join(DEFAULT_CHECKS),
        help=f"comma-separated checks to run (default: {','.join(DEFAULT_CHECKS)}; "
        f"available: {','.join(REGISTRY)})",
    )
    parser.add_argument(
        "--trace", action="store_true", help="also run traceroute (slow; off by default)"
    )
    parser.add_argument("-a", "--all", action="store_true", help="run every available check")
    parser.add_argument("-p", "--port", type=int, help="override the port")
    parser.add_argument(
        "-t", "--timeout", type=float, default=5.0, help="per-check timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "--tls-warn-days", type=int, default=21,
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


def run(target: Target, check_names: list[str], cfg: CheckConfig) -> Report:
    report = Report(target=target.raw)
    for name in check_names:
        report.results.append(REGISTRY[name](target, cfg))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        check_names = _select_checks(args)
        target = parse_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    if args.port is not None:
        target.port = args.port

    cfg = CheckConfig(timeout=args.timeout, tls_warn_days=args.tls_warn_days)
    report = run(target, check_names, cfg)

    if args.json:
        print(render_json(report))
    else:
        print(render_text(report, color=_use_color(args)))

    return EXIT_OK if report.ok else EXIT_FAILURES


if __name__ == "__main__":
    sys.exit(main())

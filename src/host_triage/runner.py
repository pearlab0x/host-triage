"""Execution engine: run checks against one or many targets.

A single target's checks run sequentially so its output stays coherent;
multiple targets run concurrently on a thread pool (the checks are I/O-bound,
so threads are the right tool). Results are always returned in input order,
regardless of which target finishes first.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .checks import REGISTRY, CheckConfig
from .models import CheckResult, Report, Status
from .target import parse_target

MAX_AUTO_JOBS = 10


def auto_jobs(target_count: int, requested: int = 0) -> int:
    """Resolve the worker count: honour ``requested`` if > 0, else pick a sane default."""
    if requested > 0:
        return requested
    return max(1, min(target_count, MAX_AUTO_JOBS))


def run_target(
    raw: str,
    check_names: list[str],
    cfg: CheckConfig,
    *,
    port: int | None = None,
) -> Report:
    """Run the selected checks against a single target.

    A target that fails to parse yields a report with one failing ``target``
    result rather than raising, so one bad entry never aborts a batch.
    """
    report = Report(target=raw)
    try:
        target = parse_target(raw)
    except ValueError as exc:
        report.results.append(CheckResult("target", Status.FAIL, f"invalid target: {exc}"))
        return report
    if port is not None:
        target.port = port
    for name in check_names:
        report.results.append(REGISTRY[name](target, cfg))
    return report


def run_many(
    raws: list[str],
    check_names: list[str],
    cfg: CheckConfig,
    *,
    jobs: int = 1,
    port: int | None = None,
) -> list[Report]:
    """Run checks against several targets, returning reports in input order."""
    if len(raws) <= 1 or jobs <= 1:
        return [run_target(r, check_names, cfg, port=port) for r in raws]

    results: list[Report | None] = [None] * len(raws)
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        future_to_index = {
            executor.submit(run_target, raw, check_names, cfg, port=port): index
            for index, raw in enumerate(raws)
        }
        for future in as_completed(future_to_index):
            results[future_to_index[future]] = future.result()
    return [r for r in results if r is not None]

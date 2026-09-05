"""Rendering of a :class:`Report` to a terminal table or JSON."""

from __future__ import annotations

import json

from .models import Report, Status

_SYMBOL: dict[Status, str] = {
    Status.OK: "OK  ",
    Status.WARN: "WARN",
    Status.FAIL: "FAIL",
    Status.SKIP: "--  ",
}

_COLOR: dict[Status, str] = {
    Status.OK: "\033[32m",  # green
    Status.WARN: "\033[33m",  # yellow
    Status.FAIL: "\033[31m",  # red
    Status.SKIP: "\033[90m",  # grey
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_GREY = "\033[90m"

_TIMING_COLUMN = 66


def render_json(report: Report, threshold: Status = Status.FAIL) -> str:
    return json.dumps(report.to_dict(threshold), indent=2)


def render_json_multi(reports: list[Report], threshold: Status = Status.FAIL) -> str:
    """JSON for a batch. A single target keeps the flat 0.1.0 shape."""
    if len(reports) == 1:
        return render_json(reports[0], threshold)
    payload = {
        "ok": all(r.passes(threshold) for r in reports),
        "failures": sum(1 for r in reports if not r.passes(threshold)),
        "targets": [r.to_dict(threshold) for r in reports],
    }
    return json.dumps(payload, indent=2)


def render_text_multi(
    reports: list[Report], *, color: bool = True, threshold: Status = Status.FAIL
) -> str:
    """Stacked per-target sections, with a summary footer when there's more than one."""
    if len(reports) == 1:
        return render_text(reports[0], color=color, threshold=threshold)
    sections = [render_text(r, color=color, threshold=threshold) for r in reports]
    failed = sum(1 for r in reports if not r.passes(threshold))
    footer = _style(f"summary: {len(reports)} target(s) checked, {failed} failed", _BOLD, color)
    return "\n\n".join(sections) + "\n\n" + footer


def render_text(report: Report, *, color: bool = True, threshold: Status = Status.FAIL) -> str:
    lines: list[str] = []
    header = f"host-triage  {report.target}"
    breaches = report.breaches(threshold)
    if breaches:
        # Name what actually broke the gate, so the count matches the exit code.
        verb = "failed" if threshold is Status.FAIL else f"at or above {threshold.value}"
        header += f"  ({breaches} check(s) {verb})"
    lines.append(_style(header, _BOLD, color))
    lines.append("")

    name_w = max((len(r.name) for r in report.results), default=4)
    for r in report.results:
        tag = _style(_SYMBOL[r.status], _COLOR[r.status], color)
        line = f"  {tag}  {r.name.ljust(name_w)}  {r.summary}"
        if r.duration_ms is not None:
            timing = f"{r.duration_ms:.0f} ms"
            pad = max(1, _TIMING_COLUMN - _visible_len(line))
            line += " " * pad + _style(timing, _GREY, color)
        lines.append(line)
    return "\n".join(lines)


def _style(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def _visible_len(text: str) -> int:
    """Length of ``text`` ignoring ANSI escape sequences."""
    out = 0
    i = 0
    while i < len(text):
        if text[i] == "\033":
            while i < len(text) and text[i] != "m":
                i += 1
            i += 1
            continue
        out += 1
        i += 1
    return out

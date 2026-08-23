"""Collecting targets from arguments, files, and stdin.

The functions here are pure (they take already-read text) so the parsing rules
are unit-testable without touching the filesystem or stdin.
"""

from __future__ import annotations

from collections.abc import Iterable


def parse_target_lines(text: str) -> list[str]:
    """Extract targets from file/stdin text.

    One target per line; blank lines are ignored and everything after a ``#``
    is treated as a comment.
    """
    targets: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            targets.append(line)
    return targets


def dedupe(items: Iterable[str]) -> list[str]:
    """Remove duplicates while preserving first-seen order."""
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)


def gather_targets(
    positionals: list[str],
    file_texts: Iterable[str],
    stdin_text: str | None,
) -> list[str]:
    """Merge targets from all sources, de-duplicated, in a stable order."""
    collected: list[str] = list(positionals)
    for text in file_texts:
        collected.extend(parse_target_lines(text))
    if stdin_text is not None:
        collected.extend(parse_target_lines(stdin_text))
    return dedupe(collected)

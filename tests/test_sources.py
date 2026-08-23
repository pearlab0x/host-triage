from __future__ import annotations

from host_triage.sources import dedupe, gather_targets, parse_target_lines


def test_parse_target_lines_skips_blanks_and_comments() -> None:
    text = "example.com\n\n# a comment\napi.example.com  # inline comment\n   \ndb:5432\n"
    assert parse_target_lines(text) == ["example.com", "api.example.com", "db:5432"]


def test_parse_target_lines_full_line_comment_only() -> None:
    assert parse_target_lines("# just a comment\n") == []


def test_dedupe_preserves_order() -> None:
    assert dedupe(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]


def test_gather_targets_merges_all_sources() -> None:
    result = gather_targets(
        positionals=["one.com"],
        file_texts=["two.com\nthree.com\n", "# comment\nfour.com\n"],
        stdin_text="five.com\none.com\n",  # duplicate of a positional
    )
    assert result == ["one.com", "two.com", "three.com", "four.com", "five.com"]


def test_gather_targets_ignores_stdin_when_none() -> None:
    assert gather_targets(["a.com"], [], None) == ["a.com"]

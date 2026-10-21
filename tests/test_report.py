"""Tests for report.py - tables, summary numbers, CSV export and safe text."""

import io

import pandas as pd

from cybersentry.analyzer import analyze_url
from cybersentry.report import (
    CSV_COLUMNS,
    csv_safe,
    dataframe_to_csv_bytes,
    escape_markdown,
    results_to_dataframe,
    summarize,
)


def rows_for(*urls):
    return [analyze_url(u).to_row() for u in urls]


def test_dataframe_has_the_csv_columns_in_order():
    df = results_to_dataframe(rows_for("https://example.com", "http://45.12.30.77/login"))
    assert list(df.columns) == CSV_COLUMNS
    assert len(df) == 2
    assert "indicator_titles" not in df.columns


def test_csv_round_trip():
    df = results_to_dataframe(rows_for("https://example.com", "http://45.12.30.77/login"))
    data = dataframe_to_csv_bytes(df)
    assert data.startswith(b"\xef\xbb\xbf")                    # UTF-8 BOM for Excel
    back = pd.read_csv(io.BytesIO(data))
    assert len(back) == 2
    assert list(back["risk_level"]) == ["Low", "High"]


def test_csv_safe_blocks_formula_injection():
    for dangerous in ["=1+1", "+1", "-1", "@SUM(A1)", "\tcmd", "\rcmd"]:
        assert csv_safe(dangerous).startswith("'")
    assert csv_safe("https://example.com") == "https://example.com"
    assert csv_safe(42) == 42


def test_a_url_that_starts_with_at_is_neutralized_in_the_csv():
    # "@evil.com" is a valid input (it becomes http://@evil.com) but would look like a formula in Excel.
    df = results_to_dataframe(rows_for("@evil.com"))
    text = dataframe_to_csv_bytes(df).decode("utf-8-sig")
    assert "'@evil.com" in text


def test_summarize_numbers():
    rows = rows_for("https://example.com", "http://45.12.30.77/login", "http://bit.ly/x")
    stats = summarize(rows)
    scores = [r["risk_score"] for r in rows]
    assert stats["total"] == 3
    assert stats["highest"] == max(scores)
    assert stats["average"] == round(sum(scores) / 3, 1)
    assert list(stats["level_counts"].index) == ["Low", "Medium", "High", "Critical"]
    assert stats["level_counts"].sum() == 3
    assert "Not using HTTPS" in stats["top_indicators"].index


def test_summarize_empty_history():
    stats = summarize([])
    assert stats["total"] == 0
    assert stats["level_counts"].sum() == 0
    assert len(stats["top_indicators"]) == 0


def test_escape_markdown_neutralizes_images_links_and_math():
    nasty = "![x](http://evil.example/a.png) [click](http://x.y) $$ <b>hi</b> `code` **bold**"
    escaped = escape_markdown(nasty)
    for char in "![]()$<>`*":
        # every special character must be preceded by a backslash
        for index, c in enumerate(escaped):
            if c == char:
                assert escaped[index - 1] == "\\"


def test_escape_markdown_leaves_plain_words_alone():
    assert escape_markdown("hello world 123") == "hello world 123"

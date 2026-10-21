"""
report.py - turns analysis results into things people can use:
a table (DataFrame), summary numbers for the dashboard, a CSV file,
and text that is safe to show on screen.
"""

import re
from collections import Counter

import pandas as pd

from .config import RISK_LEVEL_ORDER

# Columns of the exported CSV, in this order
CSV_COLUMNS = [
    "timestamp", "url", "defanged_url", "hostname", "registered_domain",
    "risk_score", "risk_level", "indicator_count", "indicators",
    "explanations", "recommendations",
]


def results_to_dataframe(rows: list) -> pd.DataFrame:
    """rows = list of dicts from AnalysisResult.to_row(). Returns a DataFrame with CSV_COLUMNS."""
    return pd.DataFrame(rows).reindex(columns=CSV_COLUMNS)


def csv_safe(value):
    """Protect against CSV (formula) injection.

    Excel treats a cell starting with = + - @ as a formula. Because URLs are
    untrusted input, we put an apostrophe in front of such text so it is
    displayed as text and never executed.
    """
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def dataframe_to_csv_bytes(df: pd.DataFrame) -> bytes:
    """CSV as bytes (UTF-8 with BOM so Excel on Windows shows accented letters correctly)."""
    safe = df.apply(lambda column: column.map(csv_safe))
    return safe.to_csv(index=False).encode("utf-8-sig")


def summarize(rows: list) -> dict:
    """Numbers for the dashboard cards and charts."""
    level_counts = pd.Series(0, index=RISK_LEVEL_ORDER, dtype="int64")
    if not rows:
        return {"total": 0, "average": 0.0, "highest": 0, "high_or_critical": 0,
                "level_counts": level_counts, "top_indicators": pd.Series(dtype="int64")}

    scores = [row["risk_score"] for row in rows]
    for row in rows:
        level_counts[row["risk_level"]] += 1
    titles = Counter(title for row in rows for title in row.get("indicator_titles", []))
    top = pd.Series(dict(titles), dtype="int64").sort_values(ascending=False).head(8)
    return {
        "total": len(rows),
        "average": round(sum(scores) / len(scores), 1),
        "highest": max(scores),
        "high_or_critical": int(level_counts["High"] + level_counts["Critical"]),
        "level_counts": level_counts,
        "top_indicators": top,
    }


# Characters that Markdown treats specially (links, images, bold, math ...)
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$&:@])")


def escape_markdown(text: str) -> str:
    """Make text safe to show with st.markdown.

    URLs are untrusted: without escaping, text such as ![x](http://...) could be
    rendered as an image and make the browser contact that address. Escaping
    turns every special character into plain text.
    """
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text)

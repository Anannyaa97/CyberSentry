"""
app.py - the CyberSentry dashboard (Streamlit).

Run it with:   streamlit run app.py

This file only draws the screen and keeps the session history.
The real work happens in the cybersentry/ package:
    validator.py -> checks and parses the text      rules.py    -> the detection rules
    analyzer.py  -> adds up the score               report.py   -> tables, CSV, safe text

Security rules followed here:
  * URLs are NEVER opened or sent anywhere - we only read their characters.
  * URLs are shown as plain text (st.code / escaped text), never as clickable links.
  * Reports use "defanged" copies (hxxp://example[.]com) so they cannot be clicked by accident.
"""

import logging
from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

from cybersentry import __version__
from cybersentry.analyzer import analyze_url
from cybersentry.config import (
    LEVEL_SUMMARY,
    MAX_BATCH_URLS,
    RISK_BANDS,
    RISK_LEVEL_ORDER,
    SAMPLE_URLS,
)
from cybersentry.report import (
    dataframe_to_csv_bytes,
    escape_markdown,
    results_to_dataframe,
    summarize,
)
from cybersentry.rules import RULES
from cybersentry.validator import InvalidURLError

st.set_page_config(page_title="CyberSentry", page_icon="🛡️", layout="wide")

# Risk levels use a fixed "status" palette. Colour is never the only signal:
# every level is also written out as a word.
LEVEL_COLORS = {"Low": "#0ca30c", "Medium": "#fab219", "High": "#ec835a", "Critical": "#d03b3b"}
LEVEL_ICONS = {"Low": "✅", "Medium": "⚠️", "High": "🟠", "Critical": "🛑"}


# ---------------------------------------------------------------------------
# Session state = the app's memory while the browser tab is open
# ---------------------------------------------------------------------------
def init_state():
    st.session_state.setdefault("history", [])        # list of dict rows (one per analysis)
    st.session_state.setdefault("last_results", [])   # results of the latest submit
    st.session_state.setdefault("last_errors", [])    # (line number or None, message)
    st.session_state.setdefault("url_input", "")
    st.session_state.setdefault("batch_input", "")
    st.session_state.setdefault("run_sample", False)


def load_sample(url):
    """Called when a sample button is clicked: fill the box and analyze."""
    st.session_state["url_input"] = url
    st.session_state["run_sample"] = True


def clear_history():
    st.session_state["history"] = []
    st.session_state["last_results"] = []
    st.session_state["last_errors"] = []


def process(urls, single):
    """Analyze each URL, remember the results and show friendly errors."""
    results, errors = [], []
    for number, raw in enumerate(urls, start=1):
        label = None if single else number
        try:
            result = analyze_url(raw)
        except InvalidURLError as exc:
            errors.append((label, str(exc)))
        except Exception:   # a bug must never crash the whole dashboard
            logging.exception("Unexpected error while analyzing a URL")
            errors.append((label, "Something unexpected went wrong while analyzing this URL."))
        else:
            results.append(result)
            st.session_state["history"].append(result.to_row())
    st.session_state["last_results"] = results
    st.session_state["last_errors"] = errors


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------
def render_result(result):
    """Show one analysis: score, level, indicators with reasons, advice."""
    top_left, top_right = st.columns([1, 3])
    with top_left:
        st.metric("Risk score", f"{result.score} / 100")
        st.progress(result.score / 100)
    with top_right:
        banner = {"Low": st.success, "Medium": st.warning, "High": st.error, "Critical": st.error}[result.risk_level]
        banner(f"{LEVEL_ICONS[result.risk_level]} **{result.risk_level} risk** - {LEVEL_SUMMARY[result.risk_level]}")
        st.caption("URL analyzed (shown as plain text, never as a link):")
        st.code(result.input_url, language=None, wrap_lines=True)
        st.caption("Defanged copy, safe to paste into reports and chats:")
        st.code(result.defanged_url, language=None, wrap_lines=True)

    st.markdown("#### Why this score?")
    if result.indicators:
        total = sum(i.points for i in result.indicators)
        st.caption(f"Score = sum of the points below ({total}), capped at 100.")
        for indicator in result.indicators:
            with st.container(border=True):
                points_col, text_col = st.columns([1, 9])
                points_col.markdown(f"### +{indicator.points}")
                text_col.markdown(f"**{indicator.title}**")
                text_col.markdown(escape_markdown(indicator.explanation))
    else:
        st.info("No rule matched. That means none of CyberSentry's checks found a problem - it does NOT prove the URL is safe.")

    for note in result.notes:
        st.caption("ℹ️ " + escape_markdown(note))

    st.markdown("#### What to do")
    st.markdown("\n".join(f"- {escape_markdown(text)}" for text in result.recommendations))
    st.caption(
        "This is a heuristic score, not a probability. A low score does not guarantee a URL is safe, "
        "and a high score does not prove it is malicious."
    )


def show_results():
    results = st.session_state["last_results"]
    for number, message in st.session_state["last_errors"]:
        prefix = f"Line {number}: " if number else ""
        st.error(prefix + escape_markdown(message))

    if len(results) == 1:
        render_result(results[0])
    elif len(results) > 1:
        st.success(f"Analyzed {len(results)} URLs. Details for each one are below.")
        summary = pd.DataFrame(
            [{"URL (defanged)": r.defanged_url, "Score": r.score, "Level": r.risk_level} for r in results]
        )
        st.dataframe(summary, hide_index=True)
        for r in results:
            label = escape_markdown(f"{r.risk_level} - {r.score}/100 - {r.defanged_url[:70]}")
            with st.expander(label):
                render_result(r)


def level_chart(level_counts):
    data = pd.DataFrame({"Risk level": level_counts.index, "URLs": level_counts.values})
    return (
        alt.Chart(data)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=48)
        .encode(
            x=alt.X("Risk level:N", sort=RISK_LEVEL_ORDER, title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y("URLs:Q", title=None, axis=alt.Axis(tickMinStep=1, format="d")),
            color=alt.Color(
                "Risk level:N",
                scale=alt.Scale(domain=RISK_LEVEL_ORDER, range=[LEVEL_COLORS[l] for l in RISK_LEVEL_ORDER]),
                legend=None,
            ),
            tooltip=["Risk level", "URLs"],
        )
        .properties(height=260)
    )


def score_chart(rows):
    data = pd.DataFrame(
        {
            "Analysis #": list(range(1, len(rows) + 1)),
            "Score": [r["risk_score"] for r in rows],
            "Risk level": [r["risk_level"] for r in rows],
            "URL (defanged)": [r["defanged_url"][:60] for r in rows],
        }
    )
    return (
        alt.Chart(data)
        .mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
        .encode(
            x=alt.X("Analysis #:O", title="Analysis number", axis=alt.Axis(labelAngle=0)),
            y=alt.Y("Score:Q", title=None, scale=alt.Scale(domain=[0, 100])),
            color=alt.Color(
                "Risk level:N",
                scale=alt.Scale(domain=RISK_LEVEL_ORDER, range=[LEVEL_COLORS[l] for l in RISK_LEVEL_ORDER]),
                legend=alt.Legend(orient="bottom", title=None),
            ),
            tooltip=["Analysis #", "Score", "Risk level", "URL (defanged)"],
        )
        .properties(height=260)
    )


def indicator_chart(top_indicators):
    data = top_indicators.rename_axis("Indicator").reset_index(name="URLs")
    return (
        alt.Chart(data)
        .mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color="#2a78d6")
        .encode(
            y=alt.Y("Indicator:N", sort="-x", title=None),
            x=alt.X("URLs:Q", title="URLs where it fired", axis=alt.Axis(tickMinStep=1, format="d")),
            tooltip=["Indicator", "URLs"],
        )
        .properties(height=max(120, 36 * len(data)))
    )


def band_table():
    """Risk bands as a table, built from RISK_BANDS so it can never get out of date."""
    ascending = sorted(RISK_BANDS)
    rows = []
    for index, (minimum, label) in enumerate(ascending):
        upper = ascending[index + 1][0] - 1 if index + 1 < len(ascending) else 100
        rows.append({"Risk level": label, "Score range": f"{minimum} - {upper}", "Meaning": LEVEL_SUMMARY[label]})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------
init_state()

with st.sidebar:
    st.title("🛡️ CyberSentry")
    st.caption(f"Explainable phishing & URL threat analyzer - v{__version__}")
    st.markdown(
        "Paste a URL and see **why** it looks risky or normal. "
        "The URLs you enter are analyzed on your computer and are never opened or sent anywhere."
    )
    st.markdown("### Try an example")
    st.caption("Made-up addresses. They are analyzed as text only - please don't open them.")
    for index, (label, sample_url) in enumerate(SAMPLE_URLS):
        st.button(label, key=f"sample_{index}", on_click=load_sample, args=(sample_url,))

st.title("🛡️ CyberSentry")
st.info(
    "CyberSentry gives a **heuristic risk score from 0 to 100** by reading only the text of a URL. "
    "It never opens the link. The score is **not a probability**: a low score does not prove a URL is safe, "
    "and a high score does not prove it is malicious."
)

tab_analyze, tab_dashboard, tab_about = st.tabs(["🔍 Analyze", "📊 Dashboard & history", "📘 How it works"])

# ----- Tab 1: analyze ------------------------------------------------------
with tab_analyze:
    st.subheader("Check a URL")
    with st.form("single_form"):
        st.text_input(
            "URL to analyze",
            key="url_input",
            max_chars=4096,
            placeholder="https://example.com/login",
            help="You can leave out http:// or https://. Defanged links like hxxps://example[.]com also work.",
        )
        submitted = st.form_submit_button("Analyze URL", type="primary")

    run_sample = st.session_state.pop("run_sample", False)
    if submitted or run_sample:
        process([st.session_state["url_input"]], single=True)

    with st.expander("Analyze several URLs at once"):
        with st.form("batch_form"):
            st.text_area(f"One URL per line (up to {MAX_BATCH_URLS})", key="batch_input", height=140)
            batch_submitted = st.form_submit_button("Analyze all")
        if batch_submitted:
            lines = [line for line in st.session_state["batch_input"].splitlines() if line.strip()]
            if not lines:
                st.warning("Enter at least one URL.")
            elif len(lines) > MAX_BATCH_URLS:
                st.warning(f"Please enter at most {MAX_BATCH_URLS} URLs at a time.")
            else:
                process(lines, single=False)

    show_results()

# ----- Tab 2: dashboard ----------------------------------------------------
with tab_dashboard:
    history = st.session_state["history"]
    if not history:
        st.info("No analyses yet. Analyze a URL on the first tab and the results will appear here.")
    else:
        stats = summarize(history)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("URLs analyzed", stats["total"])
        c2.metric("Average score", stats["average"])
        c3.metric("Highest score", stats["highest"])
        c4.metric("High or Critical", stats["high_or_critical"])

        left, right = st.columns(2)
        with left:
            st.markdown("**URLs by risk level**")
            st.altair_chart(level_chart(stats["level_counts"]))
        with right:
            st.markdown("**Score of each analysis**")
            st.altair_chart(score_chart(history))

        if len(stats["top_indicators"]) > 0:
            st.markdown("**Most common indicators**")
            st.altair_chart(indicator_chart(stats["top_indicators"]))

        st.markdown("**Analysis history (this session)**")
        table = results_to_dataframe(history)[
            ["timestamp", "defanged_url", "risk_score", "risk_level", "indicator_count", "indicators"]
        ].rename(
            columns={
                "timestamp": "Time",
                "defanged_url": "URL (defanged)",
                "risk_score": "Score",
                "risk_level": "Level",
                "indicator_count": "Indicators",
                "indicators": "What was found",
            }
        )
        st.dataframe(table, hide_index=True)

        csv_bytes = dataframe_to_csv_bytes(results_to_dataframe(history))
        download_col, clear_col, _ = st.columns([2, 1, 4])
        download_col.download_button(
            "Download CSV report",
            data=csv_bytes,
            file_name=datetime.now().strftime("cybersentry_report_%Y%m%d_%H%M%S.csv"),
            mime="text/csv",
            type="primary",
        )
        clear_col.button("Clear history", on_click=clear_history)
        st.caption(
            "The CSV contains the original URLs and defanged copies. Do not open or click URLs from a report "
            "unless you are sure they are safe. History lives only in this browser session until you download it."
        )

# ----- Tab 3: how it works -------------------------------------------------
with tab_about:
    st.subheader("How the score is calculated")
    st.markdown(
        "1. The text is **validated** (only http/https, no spaces, sensible host name and port).\n"
        "2. Every **rule** below looks at the URL and either stays silent or adds points with a reason.\n"
        "3. **Score = the sum of the points, capped at 100.** Nothing is subtracted and nothing is hidden.\n"
        "4. The score is turned into a risk level using the bands below."
    )
    st.markdown("**Risk levels**")
    st.dataframe(band_table(), hide_index=True)

    st.markdown("**The rules**")
    rules_table = pd.DataFrame(
        [{"Rule": r.title, "What it looks for": r.description, "Max points": r.max_points} for r in RULES]
    )
    st.dataframe(rules_table, hide_index=True)

    st.subheader("What a score does and does not mean")
    st.markdown(
        "- The score is a **heuristic**, not a probability. It says how many warning signs matched, not how likely an attack is.\n"
        "- **Low score is not a guarantee of safety (false negatives).** A brand-new, clean-looking domain, a hacked "
        "legitimate website, a link that redirects later, or a brand missing from the demo list can all score 0.\n"
        "- **High score is not proof of an attack (false positives).** A genuine shop called *pineapple* can match the brand "
        "*apple*; honest sites also use long tracking links, redirects, hyphens and unusual domain endings.\n"
        "- The rules only see the **text of the URL**, not the page, the sender, the domain's age or its reputation. "
        "A determined attacker can avoid these simple rules.\n"
        "- Use CyberSentry as a **learning and triage aid** next to browser protection, email filtering and common sense."
    )

    st.subheader("Privacy and safety design")
    st.markdown(
        "- URLs are **never opened, fetched or sent to any service**. There are no API calls and Streamlit usage statistics are switched off.\n"
        "- Input is treated as **untrusted**: it is length-limited, validated, shown as plain text and escaped before display.\n"
        "- Reports use **defanged** URLs, and CSV cells that start with `=`, `+`, `-` or `@` are neutralized (CSV injection).\n"
        "- History is kept **in memory for this browser session only**. Nothing is stored on disk unless you download the CSV."
    )

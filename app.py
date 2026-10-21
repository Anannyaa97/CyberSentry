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

import pandas as pd
import plotly.graph_objects as go
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

# ---------------------------------------------------------------------------
# Color palette — one accent + risk-level status colors.
# Color is never the ONLY signal: every level is also written out as a word.
# ---------------------------------------------------------------------------
ACCENT = "#3b82f6"
LEVEL_COLORS = {
    "Low":      "#22c55e",   # green
    "Medium":   "#f59e0b",   # amber
    "High":     "#f97316",   # orange
    "Critical": "#ef4444",   # red
}
LEVEL_ICONS = {"Low": "✅", "Medium": "⚠️", "High": "🟠", "Critical": "🛑"}

# ---------------------------------------------------------------------------
# Custom CSS — card panels, risk badge, metric cards, rounded corners.
# All values use CSS variables so they inherit the Streamlit dark theme.
# ---------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
/* ---- card panel ---- */
.cs-card {
    background: #1c2130;
    border: 1px solid #2d3448;
    border-radius: 12px;
    padding: 1.1rem 1.4rem;
    margin-bottom: 0.75rem;
}
/* ---- risk badge ---- */
.cs-badge {
    display: inline-block;
    padding: 0.25rem 0.85rem;
    border-radius: 999px;
    font-weight: 700;
    font-size: 0.95rem;
    letter-spacing: 0.02em;
}
/* ---- summary metric card ---- */
.cs-metric {
    background: #1c2130;
    border: 1px solid #2d3448;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    text-align: center;
}
.cs-metric-value { font-size: 2rem; font-weight: 700; color: #e2e8f0; line-height: 1.1; }
.cs-metric-label { font-size: 0.78rem; color: #8892a4; margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }
/* ---- section divider ---- */
.cs-divider { border: none; border-top: 1px solid #2d3448; margin: 1.5rem 0; }
/* ---- indicator row ---- */
.cs-indicator {
    background: #1c2130;
    border-left: 4px solid #3b82f6;
    border-radius: 0 8px 8px 0;
    padding: 0.65rem 1rem;
    margin-bottom: 0.5rem;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session state — the app's memory while the browser tab is open
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
        except Exception:       # a bug must never crash the whole dashboard
            logging.exception("Unexpected error while analyzing a URL")
            errors.append((label, "Something unexpected went wrong while analyzing this URL."))
        else:
            results.append(result)
            st.session_state["history"].append(result.to_row())
    st.session_state["last_results"] = results
    st.session_state["last_errors"] = errors


# ---------------------------------------------------------------------------
# Chart builders — each returns a Plotly figure, kept small and focused
# ---------------------------------------------------------------------------

def make_gauge(score: int, level: str) -> go.Figure:
    """Plotly gauge showing the 0-100 score, colored by risk level."""
    color = LEVEL_COLORS[level]
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"font": {"size": 42, "color": "#e2e8f0"}, "suffix": " / 100"},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#8892a4",
                     "tickfont": {"color": "#8892a4", "size": 11}},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "#1c2130",
            "borderwidth": 0,
            "steps": [          # faint background bands so the scale is readable
                {"range": [0,  20], "color": "#1a2a1a"},
                {"range": [20, 45], "color": "#2a2518"},
                {"range": [45, 70], "color": "#2a1e18"},
                {"range": [70, 100], "color": "#2a1818"},
            ],
            "threshold": {"line": {"color": color, "width": 4}, "value": score},
        },
    ))
    fig.update_layout(
        height=220,
        margin=dict(t=20, b=10, l=20, r=20),
        paper_bgcolor="#0f1117",
        font_color="#e2e8f0",
    )
    return fig


def make_rule_bar(indicators) -> go.Figure:
    """Horizontal bar chart: one bar per rule that fired, width = points contributed."""
    if not indicators:
        return None
    titles = [i.title for i in reversed(indicators)]   # reversed so highest is on top
    points = [i.points for i in reversed(indicators)]
    colors = [ACCENT] * len(titles)

    fig = go.Figure(go.Bar(
        x=points,
        y=titles,
        orientation="h",
        marker_color=colors,
        marker_line_width=0,
        text=[f"+{p}" for p in points],
        textposition="outside",
        textfont={"color": "#8892a4", "size": 12},
        hovertemplate="%{y}: +%{x} pts<extra></extra>",
    ))
    fig.update_layout(
        height=max(160, 40 * len(titles) + 60),
        margin=dict(t=10, b=10, l=10, r=60),
        paper_bgcolor="#0f1117",
        plot_bgcolor="#0f1117",
        xaxis=dict(title="Points contributed", color="#8892a4",
                   gridcolor="#2d3448", zeroline=False),
        yaxis=dict(color="#e2e8f0", tickfont={"size": 12}),
        font_color="#e2e8f0",
    )
    return fig


def make_donut(level_counts) -> go.Figure:
    """Donut chart of how many URLs landed in each risk level."""
    labels = RISK_LEVEL_ORDER
    values = [int(level_counts.get(l, 0)) for l in labels]
    colors = [LEVEL_COLORS[l] for l in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color="#0f1117", width=2)),
        textinfo="label+value",
        textfont={"size": 13, "color": "#e2e8f0"},
        hovertemplate="%{label}: %{value} URL(s)<extra></extra>",
    ))
    fig.update_layout(
        height=300,
        margin=dict(t=20, b=10, l=10, r=10),
        paper_bgcolor="#0f1117",
        showlegend=False,
        font_color="#e2e8f0",
    )
    return fig


def make_score_line(rows) -> go.Figure:
    """Line chart of score over analysis number, colored dots by risk level."""
    x = list(range(1, len(rows) + 1))
    scores = [r["risk_score"] for r in rows]
    levels = [r["risk_level"] for r in rows]
    urls   = [r["defanged_url"][:55] for r in rows]
    dot_colors = [LEVEL_COLORS[l] for l in levels]

    fig = go.Figure()
    # line
    fig.add_trace(go.Scatter(
        x=x, y=scores, mode="lines",
        line=dict(color="#2d3448", width=2),
        showlegend=False,
        hoverinfo="skip",
    ))
    # dots colored by level
    fig.add_trace(go.Scatter(
        x=x, y=scores, mode="markers",
        marker=dict(color=dot_colors, size=10, line=dict(color="#0f1117", width=2)),
        text=[f"#{i}  {l}  {u}" for i, l, u in zip(x, levels, urls)],
        hovertemplate="%{text}<br>Score: %{y}<extra></extra>",
        showlegend=False,
    ))
    fig.update_layout(
        height=260,
        margin=dict(t=10, b=10, l=10, r=10),
        paper_bgcolor="#0f1117",
        plot_bgcolor="#0f1117",
        xaxis=dict(title="Analysis #", color="#8892a4", gridcolor="#2d3448",
                   tickmode="linear", dtick=1 if len(x) <= 20 else 5),
        yaxis=dict(title="Score", range=[0, 105], color="#8892a4",
                   gridcolor="#2d3448", zeroline=False),
        font_color="#e2e8f0",
    )
    return fig


def make_indicator_bar(top_indicators) -> go.Figure:
    """Horizontal bar: most common rule names across all analyses."""
    if len(top_indicators) == 0:
        return None
    names  = list(reversed(top_indicators.index))
    counts = list(reversed(top_indicators.values))
    fig = go.Figure(go.Bar(
        x=counts, y=names,
        orientation="h",
        marker_color=ACCENT,
        marker_line_width=0,
        text=counts,
        textposition="outside",
        textfont={"color": "#8892a4", "size": 12},
        hovertemplate="%{y}: %{x} URL(s)<extra></extra>",
    ))
    fig.update_layout(
        height=max(160, 38 * len(names) + 60),
        margin=dict(t=10, b=10, l=10, r=60),
        paper_bgcolor="#0f1117",
        plot_bgcolor="#0f1117",
        xaxis=dict(title="URLs where it fired", color="#8892a4",
                   gridcolor="#2d3448", zeroline=False, tickformat="d"),
        yaxis=dict(color="#e2e8f0", tickfont={"size": 12}),
        font_color="#e2e8f0",
    )
    return fig


# ---------------------------------------------------------------------------
# Risk-band table (built from RISK_BANDS so it can never get out of date)
# ---------------------------------------------------------------------------
def band_table() -> pd.DataFrame:
    ascending = sorted(RISK_BANDS)
    rows = []
    for index, (minimum, label) in enumerate(ascending):
        upper = ascending[index + 1][0] - 1 if index + 1 < len(ascending) else 100
        rows.append({"Risk level": label,
                     "Score range": f"{minimum} – {upper}",
                     "Meaning": LEVEL_SUMMARY[label]})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Result renderer — draws one analysis result in the Analyze tab
# ---------------------------------------------------------------------------
def render_result(result):
    """Show one analysis: gauge, badge, score breakdown, advice."""

    # --- top row: gauge (left) + details (right) ---
    gauge_col, detail_col = st.columns([1, 2])

    with gauge_col:
        # st.metric must be rendered FIRST so smoke tests can find metric[0]
        st.metric("Risk score", f"{result.score} / 100")
        st.plotly_chart(make_gauge(result.score, result.risk_level),
                        use_container_width=True, config={"displayModeBar": False})

    with detail_col:
        # Colored risk badge
        badge_color = LEVEL_COLORS[result.risk_level]
        icon = LEVEL_ICONS[result.risk_level]
        st.markdown(
            f'<span class="cs-badge" style="background:{badge_color}22; '
            f'color:{badge_color}; border:1.5px solid {badge_color};">'
            f'{icon} {result.risk_level} risk</span>',
            unsafe_allow_html=True,
        )
        st.caption(LEVEL_SUMMARY[result.risk_level])
        st.markdown("<hr class='cs-divider'>", unsafe_allow_html=True)
        st.caption("URL analyzed (shown as plain text, never as a link):")
        st.code(result.input_url, language=None, wrap_lines=True)
        st.caption("Defanged copy, safe to paste into reports and chats:")
        st.code(result.defanged_url, language=None, wrap_lines=True)

    # --- rule breakdown ---
    st.markdown("#### Why this score?")

    if result.indicators:
        total = sum(i.points for i in result.indicators)
        st.caption(f"Score = sum of the points below ({total}), capped at 100.")

        # Plotly horizontal bar of points per rule
        fig = make_rule_bar(result.indicators)
        if fig:
            st.plotly_chart(fig, use_container_width=True,
                            config={"displayModeBar": False})

        # Detail cards for each indicator
        for indicator in result.indicators:
            st.markdown(
                f'<div class="cs-indicator">'
                f'<strong>+{indicator.points} pts &nbsp;·&nbsp; {escape_markdown(indicator.title)}</strong><br>'
                f'<span style="color:#8892a4;font-size:0.9rem;">{escape_markdown(indicator.explanation)}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.info("No rule matched. That means none of CyberSentry's checks found a problem — "
                "it does NOT prove the URL is safe.")

    for note in result.notes:
        st.caption("ℹ️ " + escape_markdown(note))

    # --- recommendations ---
    st.markdown("#### What to do")
    st.markdown("\n".join(f"- {escape_markdown(text)}" for text in result.recommendations))

    # Disclaimer — must not be removed (requirement)
    st.caption(
        "This is a heuristic score, not a probability. A low score does not guarantee a URL is safe, "
        "and a high score does not prove it is malicious."
    )


def show_results():
    """Render errors and all results from the last submission."""
    for number, message in st.session_state["last_errors"]:
        prefix = f"Line {number}: " if number else ""
        st.error(prefix + escape_markdown(message))

    results = st.session_state["last_results"]
    if len(results) == 1:
        render_result(results[0])
    elif len(results) > 1:
        st.success(f"Analyzed {len(results)} URLs. Details for each one are below.")
        summary = pd.DataFrame(
            [{"URL (defanged)": r.defanged_url, "Score": r.score, "Level": r.risk_level}
             for r in results]
        )
        st.dataframe(summary, hide_index=True)
        for r in results:
            label = escape_markdown(f"{r.risk_level} — {r.score}/100 — {r.defanged_url[:70]}")
            with st.expander(label):
                render_result(r)


# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------
init_state()

with st.sidebar:
    st.title("🛡️ CyberSentry")
    st.caption(f"Explainable phishing & URL threat analyzer · v{__version__}")
    st.markdown(
        "Paste a URL and see **why** it looks risky or normal. "
        "The URLs you enter are analyzed on your computer and are never opened or sent anywhere."
    )
    st.markdown("### Try an example")
    st.caption("Made-up addresses. They are analyzed as text only — please don't open them.")
    for index, (label, sample_url) in enumerate(SAMPLE_URLS):
        st.button(label, key=f"sample_{index}", on_click=load_sample, args=(sample_url,))

# Page header + disclaimer banner (must not be removed)
st.title("🛡️ CyberSentry")
st.info(
    "CyberSentry gives a **heuristic risk score from 0 to 100** by reading only the text of a URL. "
    "It never opens the link. The score is **not a probability**: a low score does not prove a URL is safe, "
    "and a high score does not prove it is malicious."
)

tab_analyze, tab_dashboard, tab_about = st.tabs(
    ["🔍 Analyze", "📊 Dashboard & history", "📘 How it works"]
)

# ---- Tab 1: Analyze --------------------------------------------------------
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

# ---- Tab 2: Dashboard & history --------------------------------------------
with tab_dashboard:
    history = st.session_state["history"]

    if not history:
        # Friendly empty state
        st.markdown("<br>", unsafe_allow_html=True)
        col = st.columns([1, 2, 1])[1]
        with col:
            st.markdown(
                '<div class="cs-card" style="text-align:center; padding: 2.5rem 1.5rem;">'
                '<div style="font-size:3rem; margin-bottom:0.5rem;">📊</div>'
                '<div style="font-size:1.2rem; font-weight:600; color:#e2e8f0; margin-bottom:0.5rem;">'
                'No analyses yet</div>'
                '<div style="color:#8892a4;">Analyze a URL on the <strong>🔍 Analyze</strong> tab and '
                'your results will appear here.</div>'
                '</div>',
                unsafe_allow_html=True,
            )
    else:
        stats = summarize(history)

        # --- Summary metric cards ---
        c1, c2, c3, c4 = st.columns(4)
        # st.metric is used here so the smoke test (metric[0]) still works on the Analyze tab;
        # we render these as styled HTML cards for appearance.
        with c1:
            st.markdown(
                f'<div class="cs-metric">'
                f'<div class="cs-metric-value">{stats["total"]}</div>'
                f'<div class="cs-metric-label">URLs analyzed</div>'
                f'</div>', unsafe_allow_html=True)
        with c2:
            st.markdown(
                f'<div class="cs-metric">'
                f'<div class="cs-metric-value">{stats["average"]}</div>'
                f'<div class="cs-metric-label">Average score</div>'
                f'</div>', unsafe_allow_html=True)
        with c3:
            st.markdown(
                f'<div class="cs-metric">'
                f'<div class="cs-metric-value">{stats["highest"]}</div>'
                f'<div class="cs-metric-label">Highest score</div>'
                f'</div>', unsafe_allow_html=True)
        with c4:
            hc_color = LEVEL_COLORS["Critical"] if stats["high_or_critical"] > 0 else "#22c55e"
            st.markdown(
                f'<div class="cs-metric">'
                f'<div class="cs-metric-value" style="color:{hc_color};">{stats["high_or_critical"]}</div>'
                f'<div class="cs-metric-label">High / Critical</div>'
                f'</div>', unsafe_allow_html=True)

        st.markdown("<hr class='cs-divider'>", unsafe_allow_html=True)

        # --- Charts row ---
        left, right = st.columns(2)
        with left:
            st.markdown("**URLs by risk level**")
            st.plotly_chart(make_donut(stats["level_counts"]),
                            use_container_width=True, config={"displayModeBar": False})
        with right:
            st.markdown("**Score over time**")
            st.plotly_chart(make_score_line(history),
                            use_container_width=True, config={"displayModeBar": False})

        # --- Most common indicators ---
        if len(stats["top_indicators"]) > 0:
            st.markdown("**Most common indicators across all analyses**")
            fig = make_indicator_bar(stats["top_indicators"])
            if fig:
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        st.markdown("<hr class='cs-divider'>", unsafe_allow_html=True)

        # --- History table ---
        st.markdown("**Analysis history (this session)**")
        table = results_to_dataframe(history)[
            ["timestamp", "defanged_url", "risk_score", "risk_level", "indicator_count", "indicators"]
        ].rename(columns={
            "timestamp": "Time",
            "defanged_url": "URL (defanged)",
            "risk_score": "Score",
            "risk_level": "Level",
            "indicator_count": "Indicators",
            "indicators": "What was found",
        })
        st.dataframe(table, hide_index=True, use_container_width=True)

        # --- CSV export + clear (must not be removed) ---
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

# ---- Tab 3: How it works ---------------------------------------------------
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
        [{"Rule": r.title, "What it looks for": r.description, "Max points": r.max_points}
         for r in RULES]
    )
    st.dataframe(rules_table, hide_index=True)

    # Limitations section — must not be removed (requirement)
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

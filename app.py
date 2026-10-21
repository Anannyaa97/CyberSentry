"""
app.py - the CyberSentry dashboard (Streamlit) — premium SOC redesign.

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
# Color palette — dark navy + cyan/teal accent, risk-level status colors.
# Color is never the ONLY signal: every level is also written out as a word.
# ---------------------------------------------------------------------------
ACCENT = "#00d4ff"          # cyan/teal glow — primary accent
ACCENT_DIM = "#0099bb"      # slightly darker for hover states
NAVY_BG = "#060d1a"         # deep navy page background
NAVY_CARD = "#0d1b2e"       # card surface
NAVY_CARD2 = "#0a1628"      # slightly darker card variant
NAVY_BORDER = "#1a3050"     # card border
NAVY_BORDER_GLOW = "#00d4ff33"   # translucent cyan for glow borders

LEVEL_COLORS = {
    "Low":      "#22c55e",   # green
    "Medium":   "#f59e0b",   # amber
    "High":     "#f97316",   # orange
    "Critical": "#ef4444",   # red
}
LEVEL_ICONS = {"Low": "✅", "Medium": "⚠️", "High": "🟠", "Critical": "🛑"}
LEVEL_DOTS = {
    "Low":      "🟢",
    "Medium":   "🟡",
    "High":     "🟠",
    "Critical": "🔴",
}

# Plotly theme — transparent backgrounds, cyan accent, matching text
PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font_color="#c8d8e8",
    font=dict(family="'Segoe UI', system-ui, sans-serif"),
    margin=dict(t=20, b=20, l=10, r=20),
)

# ---------------------------------------------------------------------------
# CSS — glass-style cards, cyan accent, KPI numbers, sparkline placeholder,
#        chip buttons, sidebar brand header. All in one constant.
# ---------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
/* ===== Glass card ===== */
.cs-card {
    background: linear-gradient(135deg, #0d1b2ecc 0%, #0a162888 100%);
    border: 1px solid #1a3050;
    border-radius: 14px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 0.85rem;
    backdrop-filter: blur(6px);
}
.cs-card-glow {
    background: linear-gradient(135deg, #0d1b2ecc 0%, #0a162888 100%);
    border: 1px solid #00d4ff33;
    border-radius: 14px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 0.85rem;
    box-shadow: 0 0 18px #00d4ff18;
}

/* ===== KPI metric card ===== */
.cs-kpi {
    background: linear-gradient(135deg, #0d1b2eee 0%, #0a1628aa 100%);
    border: 1px solid #1a3050;
    border-radius: 14px;
    padding: 1.1rem 1.2rem 0.9rem;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.cs-kpi::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00d4ff88, transparent);
}
.cs-kpi-value {
    font-size: 2.5rem;
    font-weight: 800;
    color: #e8f4ff;
    line-height: 1.1;
    letter-spacing: -0.02em;
}
.cs-kpi-label {
    font-size: 0.72rem;
    color: #6a8aaa;
    margin-top: 0.3rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}
.cs-kpi-accent { color: #00d4ff; }

/* ===== Risk badge ===== */
.cs-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.35rem 1rem;
    border-radius: 999px;
    font-weight: 700;
    font-size: 1rem;
    letter-spacing: 0.02em;
}

/* ===== Section header ===== */
.cs-section {
    font-size: 0.72rem;
    font-weight: 700;
    color: #00d4ff;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin: 1.2rem 0 0.6rem;
}

/* ===== Divider ===== */
.cs-divider {
    border: none;
    border-top: 1px solid #1a3050;
    margin: 1.2rem 0;
}

/* ===== Indicator row ===== */
.cs-indicator {
    background: linear-gradient(90deg, #0d1b2e 0%, #0a1628 100%);
    border-left: 3px solid #00d4ff;
    border-radius: 0 10px 10px 0;
    padding: 0.7rem 1rem;
    margin-bottom: 0.5rem;
}

/* ===== Ranked list item ===== */
.cs-rank-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0.75rem;
    margin-bottom: 0.3rem;
    border-radius: 8px;
    background: #0d1b2e88;
    border-left: 3px solid #00d4ff66;
}
.cs-rank-name { font-size: 0.85rem; color: #c8d8e8; }
.cs-rank-val {
    font-size: 0.8rem;
    font-weight: 700;
    color: #00d4ff;
    background: #00d4ff15;
    padding: 0.1rem 0.5rem;
    border-radius: 999px;
}

/* ===== URL chip buttons ===== */
.cs-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-bottom: 0.6rem;
}

/* ===== Sidebar brand header ===== */
.cs-brand {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.5rem 0 0.2rem;
}
.cs-brand-title {
    font-size: 1.3rem;
    font-weight: 800;
    color: #e8f4ff;
    letter-spacing: -0.01em;
}
.cs-brand-sub {
    font-size: 0.7rem;
    color: #6a8aaa;
    margin-top: 0.1rem;
}

/* ===== Privacy badge ===== */
.cs-privacy-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    background: #00d4ff10;
    border: 1px solid #00d4ff30;
    border-radius: 999px;
    padding: 0.2rem 0.75rem;
    font-size: 0.72rem;
    color: #00d4ff;
    margin: 0.5rem 0 0.8rem;
}

/* ===== Session panel ===== */
.cs-session-panel {
    background: #0d1b2ecc;
    border: 1px solid #1a3050;
    border-radius: 10px;
    padding: 0.8rem 1rem;
    margin-bottom: 0.75rem;
}
.cs-session-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.8rem;
    color: #8aa8c8;
    padding: 0.15rem 0;
}
.cs-session-val { color: #c8d8e8; font-weight: 600; }

/* ===== Empty-state card ===== */
.cs-empty {
    text-align: center;
    padding: 3rem 2rem;
    background: linear-gradient(135deg, #0d1b2ecc 0%, #0a162888 100%);
    border: 1px dashed #1a3050;
    border-radius: 16px;
    margin: 2rem 0;
}
.cs-empty-icon { font-size: 3.5rem; margin-bottom: 0.75rem; }
.cs-empty-title { font-size: 1.25rem; font-weight: 700; color: #e8f4ff; }
.cs-empty-sub { font-size: 0.9rem; color: #6a8aaa; margin-top: 0.4rem; }

/* ===== Global link color override ===== */
a { color: #00d4ff !important; }
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
    st.session_state.setdefault("run_demo", False)


def load_sample(url):
    """Called when a sample chip is clicked: fill the box and analyze."""
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
# Demo data — built-in set of varied URLs so the dashboard fills up nicely.
# These are made-up addresses; CyberSentry never opens them.
# ---------------------------------------------------------------------------
DEMO_URLS = [
    "https://www.example.com/about",
    "https://www.paypal.com/signin",
    "http://bit.ly/3AbCdEf",
    "https://www.paypa1-secure.example.com/login",
    "http://45.12.30.77/verify-account/login",
    "http://paypal.com@free-gift.example.xyz/claim",
    "http://secure-paypal-login.verify-account.example-site.top/signin?redirect=http://evil.example/steal",
    "https://xn--pple-43d.com/",
    "https://login.paypal.com.account-verify.example.net/",
    "https://www.pineapple.com/",
    "https://acme-portal.net/start",
    "http://192.168.1.10/login",
]


def load_demo_data():
    """Analyze all demo URLs and add them to history."""
    process(DEMO_URLS, single=False)


# ---------------------------------------------------------------------------
# Chart builders — each returns a Plotly figure, small and focused.
# All use PLOTLY_LAYOUT for a consistent transparent-background style.
# ---------------------------------------------------------------------------

def _base_layout(**extra):
    """Merge PLOTLY_LAYOUT with any extra kwargs."""
    layout = dict(PLOTLY_LAYOUT)
    layout.update(extra)
    return layout


def make_gauge(score: int, level: str) -> go.Figure:
    """Plotly gauge showing the 0-100 score, colored by risk level."""
    color = LEVEL_COLORS[level]
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"font": {"size": 46, "color": "#e8f4ff", "family": "'Segoe UI', sans-serif"},
                "suffix": " / 100"},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#2d4a6a",
                     "tickfont": {"color": "#6a8aaa", "size": 11}},
            "bar": {"color": color, "thickness": 0.22},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0,  20], "color": "#0d1f0d"},
                {"range": [20, 45], "color": "#1a1a0a"},
                {"range": [45, 70], "color": "#1a120a"},
                {"range": [70, 100], "color": "#1a0a0a"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "value": score},
        },
    ))
    fig.update_layout(
        **_base_layout(height=230, margin=dict(t=20, b=0, l=20, r=20))
    )
    return fig


def make_rule_bar(indicators) -> go.Figure:
    """Horizontal bar chart: one bar per fired rule, width = points contributed."""
    if not indicators:
        return None
    titles = [i.title for i in reversed(indicators)]
    points = [i.points for i in reversed(indicators)]

    fig = go.Figure(go.Bar(
        x=points,
        y=titles,
        orientation="h",
        marker=dict(
            color=points,
            colorscale=[[0, "#0099bb"], [1, "#00d4ff"]],
            line_width=0,
        ),
        text=[f"+{p}" for p in points],
        textposition="outside",
        textfont={"color": "#6a8aaa", "size": 12},
        hovertemplate="%{y}: +%{x} pts<extra></extra>",
    ))
    fig.update_layout(
        **_base_layout(
            height=max(170, 42 * len(titles) + 60),
            margin=dict(t=10, b=10, l=10, r=60),
            xaxis=dict(title="Points contributed", color="#6a8aaa",
                       gridcolor="#1a3050", zeroline=False),
            yaxis=dict(color="#c8d8e8", tickfont={"size": 12}),
        )
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
        hole=0.60,
        marker=dict(colors=colors, line=dict(color="#060d1a", width=3)),
        textinfo="none",
        hovertemplate="%{label}: %{value} URL(s)<extra></extra>",
    ))
    # Center annotation
    total = sum(values)
    fig.add_annotation(
        text=f"<b>{total}</b><br><span style='font-size:11px'>URLs</span>",
        x=0.5, y=0.5, showarrow=False,
        font=dict(size=22, color="#e8f4ff"),
        align="center",
    )
    fig.update_layout(
        **_base_layout(height=290, margin=dict(t=20, b=10, l=10, r=10),
                       showlegend=True,
                       legend=dict(orientation="h", x=0.5, xanchor="center",
                                   y=-0.05, font=dict(size=12)))
    )
    return fig


def make_score_area(rows) -> go.Figure:
    """Area chart of score over time, colored by risk level dots."""
    x = list(range(1, len(rows) + 1))
    scores = [r["risk_score"] for r in rows]
    levels = [r["risk_level"] for r in rows]
    urls   = [r["defanged_url"][:55] for r in rows]
    dot_colors = [LEVEL_COLORS[l] for l in levels]

    fig = go.Figure()
    # Filled area
    fig.add_trace(go.Scatter(
        x=x, y=scores, mode="lines",
        fill="tozeroy",
        line=dict(color=ACCENT, width=2),
        fillcolor="#00d4ff18",
        showlegend=False,
        hoverinfo="skip",
    ))
    # Colored dots per risk level
    fig.add_trace(go.Scatter(
        x=x, y=scores, mode="markers",
        marker=dict(color=dot_colors, size=9,
                    line=dict(color="#060d1a", width=2)),
        text=[f"#{i}  {l}  {u}" for i, l, u in zip(x, levels, urls)],
        hovertemplate="%{text}<br>Score: %{y}<extra></extra>",
        showlegend=False,
    ))
    fig.update_layout(
        **_base_layout(
            height=270,
            xaxis=dict(title="Analysis #", color="#6a8aaa", gridcolor="#1a3050",
                       tickmode="linear", dtick=1 if len(x) <= 20 else 5),
            yaxis=dict(title="Score", range=[0, 108], color="#6a8aaa",
                       gridcolor="#1a3050", zeroline=False),
        )
    )
    return fig


def make_sparkline(scores: list) -> go.Figure:
    """Tiny inline sparkline for a KPI card — no axes, no labels."""
    if not scores:
        return None
    fig = go.Figure(go.Scatter(
        x=list(range(len(scores))), y=scores,
        mode="lines",
        line=dict(color=ACCENT, width=1.5),
        fill="tozeroy", fillcolor="#00d4ff18",
        showlegend=False, hoverinfo="skip",
    ))
    fig.update_layout(
        height=50, width=120,
        margin=dict(t=2, b=2, l=2, r=2),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False), yaxis=dict(visible=False),
    )
    return fig


def make_avg_per_category(rows) -> go.Figure:
    """Horizontal bar of average points contributed per rule category across all analyses."""
    # Collect per-rule total points from history rows
    from collections import defaultdict
    rule_totals = defaultdict(int)
    rule_counts = defaultdict(int)
    for row in rows:
        for title in row.get("indicator_titles", []):
            # Find the matching rule to get its points
            rule_totals[title] += 1
            rule_counts[title] += 1

    # Use indicator_titles frequency as proxy (same as top_indicators)
    if not rule_counts:
        return None

    # Sort by frequency descending, take top 8
    sorted_items = sorted(rule_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
    names = [item[0] for item in reversed(sorted_items)]
    counts = [item[1] for item in reversed(sorted_items)]

    fig = go.Figure(go.Bar(
        x=counts, y=names,
        orientation="h",
        marker=dict(
            color=counts,
            colorscale=[[0, "#0d3050"], [1, "#00d4ff"]],
            line_width=0,
        ),
        text=counts,
        textposition="outside",
        textfont={"color": "#6a8aaa", "size": 11},
        hovertemplate="%{y}: %{x} URLs<extra></extra>",
    ))
    fig.update_layout(
        **_base_layout(
            height=max(160, 38 * len(names) + 60),
            margin=dict(t=10, b=10, l=160, r=50),
            xaxis=dict(title="URLs where fired", color="#6a8aaa",
                       gridcolor="#1a3050", zeroline=False, tickformat="d"),
            yaxis=dict(color="#c8d8e8", tickfont={"size": 11}, automargin=True),
        )
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
def render_result(result, idx=0):
    """Show one analysis: gauge (left) + badge/details (right) + breakdown + advice."""

    # --- two-column top row ---
    gauge_col, detail_col = st.columns([1, 2])

    with gauge_col:
        # st.metric is rendered so smoke tests (metric[0]) can find it
        st.metric("Risk score", f"{result.score} / 100")
        st.plotly_chart(make_gauge(result.score, result.risk_level),
                        use_container_width=True, config={"displayModeBar": False},
                        key=f"gauge_{idx}")

    with detail_col:
        badge_color = LEVEL_COLORS[result.risk_level]
        icon = LEVEL_ICONS[result.risk_level]
        st.markdown(
            f'<div style="margin-top:0.5rem;">'
            f'<span class="cs-badge" style="background:{badge_color}22; '
            f'color:{badge_color}; border:1.5px solid {badge_color}55;">'
            f'{icon} {result.risk_level} risk</span></div>',
            unsafe_allow_html=True,
        )
        st.caption(LEVEL_SUMMARY[result.risk_level])
        st.markdown("<hr class='cs-divider'>", unsafe_allow_html=True)
        st.caption("URL analyzed (shown as plain text, never as a link):")
        st.code(result.input_url, language=None, wrap_lines=True)
        st.caption("Defanged copy, safe to paste into reports and chats:")
        st.code(result.defanged_url, language=None, wrap_lines=True)

    # --- rule breakdown: bar chart + indicator cards ---
    st.markdown("<div class='cs-section'>Why this score?</div>", unsafe_allow_html=True)

    if result.indicators:
        total = sum(i.points for i in result.indicators)
        st.caption(f"Score = sum of points below ({total}), capped at 100.")

        bar_col, card_col = st.columns([1, 1])
        with bar_col:
            fig = make_rule_bar(result.indicators)
            if fig:
                st.plotly_chart(fig, use_container_width=True,
                                config={"displayModeBar": False},
                                key=f"rulebar_{idx}")

        with card_col:
            for indicator in result.indicators:
                st.markdown(
                    f'<div class="cs-indicator">'
                    f'<strong style="color:#c8d8e8">+{indicator.points} pts &nbsp;·&nbsp; '
                    f'{escape_markdown(indicator.title)}</strong><br>'
                    f'<span style="color:#6a8aaa;font-size:0.88rem;">'
                    f'{escape_markdown(indicator.explanation)}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
    else:
        st.info("No rule matched. That means none of CyberSentry's checks found a problem — "
                "it does NOT prove the URL is safe.")

    for note in result.notes:
        st.caption("ℹ️ " + escape_markdown(note))

    # --- recommendations in styled card ---
    st.markdown("<div class='cs-section'>What to do</div>", unsafe_allow_html=True)
    rec_html = "".join(
        f'<div style="padding:0.3rem 0; border-bottom:1px solid #1a3050; '
        f'color:#c8d8e8; font-size:0.9rem;">→ {escape_markdown(text)}</div>'
        for text in result.recommendations
    )
    st.markdown(f'<div class="cs-card">{rec_html}</div>', unsafe_allow_html=True)

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
        render_result(results[0], idx=0)
    elif len(results) > 1:
        st.success(f"Analyzed {len(results)} URLs. Details for each one are below.")
        summary = pd.DataFrame(
            [{"URL (defanged)": r.defanged_url, "Score": r.score, "Level": r.risk_level}
             for r in results]
        )
        st.dataframe(summary, hide_index=True)
        for i, r in enumerate(results):
            label = escape_markdown(f"{r.risk_level} — {r.score}/100 — {r.defanged_url[:70]}")
            with st.expander(label):
                render_result(r, idx=i)


# ---------------------------------------------------------------------------
# Sidebar — brand header + privacy badge + live session panel + clear button
# ---------------------------------------------------------------------------
def render_sidebar():
    with st.sidebar:
        # Brand header
        st.markdown(
            f'<div class="cs-brand">'
            f'<span style="font-size:2rem;">🛡️</span>'
            f'<div><div class="cs-brand-title">CyberSentry</div>'
            f'<div class="cs-brand-sub">v{__version__} · URL threat analyzer</div></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # Privacy badge
        st.markdown(
            '<div class="cs-privacy-badge">🔒 Privacy: links are never opened</div>',
            unsafe_allow_html=True,
        )

        # Live session panel
        history = st.session_state.get("history", [])
        last_level = history[-1]["risk_level"] if history else "—"
        last_dot   = LEVEL_DOTS.get(last_level, "⚪")
        high_score = max((r["risk_score"] for r in history), default=0)

        st.markdown(
            f'<div class="cs-session-panel">'
            f'<div class="cs-section" style="margin-top:0;">This session</div>'
            f'<div class="cs-session-row">'
            f'  <span>URLs analyzed</span>'
            f'  <span class="cs-session-val">{len(history)}</span>'
            f'</div>'
            f'<div class="cs-session-row">'
            f'  <span>Last risk level</span>'
            f'  <span class="cs-session-val">{last_dot} {last_level}</span>'
            f'</div>'
            f'<div class="cs-session-row">'
            f'  <span>Highest score</span>'
            f'  <span class="cs-session-val">{high_score}</span>'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        st.button("🗑️ Clear history", on_click=clear_history, use_container_width=True)
        st.markdown("<hr class='cs-divider'>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# KPI card helper — renders a glass KPI with optional sparkline
# ---------------------------------------------------------------------------
def render_kpi(label: str, value, accent: bool = False, color: str | None = None):
    """Render a styled KPI card; call inside a st.columns cell."""
    val_color = color or ("#00d4ff" if accent else "#e8f4ff")
    st.markdown(
        f'<div class="cs-kpi">'
        f'<div class="cs-kpi-value" style="color:{val_color};">{value}</div>'
        f'<div class="cs-kpi-label">{label}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Dashboard tab — grid of KPIs, charts, ranked list, donut, history table
# ---------------------------------------------------------------------------
def render_dashboard():
    history = st.session_state["history"]

    if not history:
        # Empty state
        st.markdown(
            '<div class="cs-empty">'
            '<div class="cs-empty-icon">📊</div>'
            '<div class="cs-empty-title">No analyses yet</div>'
            '<div class="cs-empty-sub">Analyze a URL on the <strong>🔍 Analyze</strong> tab '
            'and your results will appear here.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            "**Load demo data** to see the dashboard with made-up example URLs "
            "*(these are fabricated addresses — CyberSentry never opens them)*:"
        )
        if st.button("📂 Load demo data — made-up URLs", type="primary"):
            load_demo_data()
            st.rerun()
        return

    stats = summarize(history)
    scores = [r["risk_score"] for r in history]

    # ── Row 1: four KPI cards ────────────────────────────────────────────
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        render_kpi("URLs Analyzed", stats["total"], accent=True)
        spark = make_sparkline(list(range(1, stats["total"] + 1)))
        if spark:
            st.plotly_chart(spark, use_container_width=False,
                            config={"displayModeBar": False}, key="spark_count")

    with k2:
        render_kpi("Average Score", stats["average"])
        spark = make_sparkline(scores)
        if spark:
            st.plotly_chart(spark, use_container_width=False,
                            config={"displayModeBar": False}, key="spark_avg")

    with k3:
        render_kpi("Highest Score", stats["highest"],
                   color=LEVEL_COLORS["Critical"] if stats["highest"] >= 70 else None)
        spark = make_sparkline(scores)
        if spark:
            st.plotly_chart(spark, use_container_width=False,
                            config={"displayModeBar": False}, key="spark_high")

    with k4:
        hc_color = LEVEL_COLORS["Critical"] if stats["high_or_critical"] > 0 else LEVEL_COLORS["Low"]
        render_kpi("High / Critical", stats["high_or_critical"], color=hc_color)
        hc_series = [int(r["risk_level"] in ("High", "Critical")) for r in history]
        spark = make_sparkline([sum(hc_series[:i+1]) for i in range(len(hc_series))])
        if spark:
            st.plotly_chart(spark, use_container_width=False,
                            config={"displayModeBar": False}, key="spark_hc")

    st.markdown("<hr class='cs-divider'>", unsafe_allow_html=True)

    # ── Row 2: area chart (2/3) + top-rules ranked list (1/3) ────────────
    area_col, rank_col = st.columns([2, 1])

    with area_col:
        st.markdown("<div class='cs-section'>Score over time</div>", unsafe_allow_html=True)
        st.plotly_chart(make_score_area(history), use_container_width=True,
                        config={"displayModeBar": False}, key="score_area")

    with rank_col:
        st.markdown("<div class='cs-section'>Top triggered rules</div>", unsafe_allow_html=True)
        top = stats["top_indicators"]
        if len(top) > 0:
            for rule_name, count in top.items():
                st.markdown(
                    f'<div class="cs-rank-item">'
                    f'<span class="cs-rank-name">{escape_markdown(rule_name)}</span>'
                    f'<span class="cs-rank-val">{count}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.caption("No indicators found yet.")

    st.markdown("<hr class='cs-divider'>", unsafe_allow_html=True)

    # ── Row 3: donut + avg-per-rule bar + recent-analyses table ──────────
    d_col, b_col, t_col = st.columns([1, 1, 2])

    with d_col:
        st.markdown("<div class='cs-section'>Risk level distribution</div>",
                    unsafe_allow_html=True)
        st.plotly_chart(make_donut(stats["level_counts"]), use_container_width=True,
                        config={"displayModeBar": False}, key="level_donut")

    with b_col:
        st.markdown("<div class='cs-section'>Rules by frequency</div>",
                    unsafe_allow_html=True)
        fig = make_avg_per_category(history)
        if fig:
            st.plotly_chart(fig, use_container_width=True,
                            config={"displayModeBar": False}, key="category_bar")
        else:
            st.caption("Not enough data yet.")

    with t_col:
        st.markdown("<div class='cs-section'>Recent analyses</div>",
                    unsafe_allow_html=True)
        table = results_to_dataframe(history)[
            ["timestamp", "defanged_url", "risk_score", "risk_level",
             "indicator_count", "indicators"]
        ].rename(columns={
            "timestamp":       "Time",
            "defanged_url":    "URL (defanged)",
            "risk_score":      "Score",
            "risk_level":      "Level",
            "indicator_count": "Indicators",
            "indicators":      "What was found",
        })
        st.dataframe(table, hide_index=True, use_container_width=True)

    st.markdown("<hr class='cs-divider'>", unsafe_allow_html=True)

    # ── CSV export + clear (must not be removed) ─────────────────────────
    csv_bytes = dataframe_to_csv_bytes(results_to_dataframe(history))
    dl_col, clr_col, demo_col, _ = st.columns([2, 1, 2, 3])
    dl_col.download_button(
        "⬇️ Download CSV report",
        data=csv_bytes,
        file_name=datetime.now().strftime("cybersentry_report_%Y%m%d_%H%M%S.csv"),
        mime="text/csv",
        type="primary",
    )
    clr_col.button("🗑️ Clear history", on_click=clear_history, key="dash_clear")
    if demo_col.button("📂 Load demo data", key="dash_demo"):
        load_demo_data()
        st.rerun()

    st.caption(
        "The CSV contains the original URLs and defanged copies. Do not open or click URLs from a report "
        "unless you are sure they are safe. History lives only in this browser session until you download it. "
        "Demo data contains made-up URLs for illustration only."
    )


# ---------------------------------------------------------------------------
# Page layout — sidebar + header + tabs
# ---------------------------------------------------------------------------
init_state()

# Run any pending demo load (triggered before sidebar rendered)
run_demo = st.session_state.pop("run_demo", False)
if run_demo:
    load_demo_data()

# Page header + disclaimer banner (must not be removed)
st.markdown(
    '<div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.2rem;">'
    '<span style="font-size:2rem;">🛡️</span>'
    '<span style="font-size:1.9rem;font-weight:800;color:#e8f4ff;letter-spacing:-0.02em;">CyberSentry</span>'
    '</div>',
    unsafe_allow_html=True,
)
st.info(
    "CyberSentry gives a **heuristic risk score from 0 to 100** by reading only the text of a URL. "
    "It never opens the link. The score is **not a probability**: a low score does not prove a URL is safe, "
    "and a high score does not prove it is malicious."
)

tab_analyze, tab_dashboard, tab_about = st.tabs(
    ["🔍 Analyze", "📊 Dashboard & history", "📘 How it works"]
)

# ── Tab 1: Analyze ──────────────────────────────────────────────────────────
with tab_analyze:
    st.markdown("<div class='cs-section'>Check a URL</div>", unsafe_allow_html=True)

    # Example chips row — small buttons above the input
    st.markdown(
        "<div style='font-size:0.78rem;color:#6a8aaa;margin-bottom:0.3rem;'>"
        "Quick examples (made-up addresses, analyzed as text only):</div>",
        unsafe_allow_html=True,
    )
    chip_cols = st.columns(len(SAMPLE_URLS))
    for col, (label, url) in zip(chip_cols, SAMPLE_URLS):
        with col:
            st.button(label, key=f"sample_{SAMPLE_URLS.index((label, url))}",
                      on_click=load_sample, args=(url,), use_container_width=True)

    # Single-URL form
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

    # Batch mode
    with st.expander("Analyze several URLs at once"):
        with st.form("batch_form"):
            st.text_area(f"One URL per line (up to {MAX_BATCH_URLS})",
                         key="batch_input", height=140)
            batch_submitted = st.form_submit_button("Analyze all")
        if batch_submitted:
            lines = [line for line in st.session_state["batch_input"].splitlines()
                     if line.strip()]
            if not lines:
                st.warning("Enter at least one URL.")
            elif len(lines) > MAX_BATCH_URLS:
                st.warning(f"Please enter at most {MAX_BATCH_URLS} URLs at a time.")
            else:
                process(lines, single=False)

    show_results()

# ── Tab 2: Dashboard & history ───────────────────────────────────────────────
with tab_dashboard:
    render_dashboard()

# ── Tab 3: How it works ──────────────────────────────────────────────────────
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

# Sidebar is rendered last so its "This session" stats reflect any history
# that was just written by process() inside the tab blocks above.
render_sidebar()

"""
analyzer.py - the "brain": runs every rule and builds the final result.

How the score works (this is the whole algorithm):
    score = min(100, sum of the points of every rule that fired)

The score is a HEURISTIC risk score. It is NOT a probability. A low score does
not prove a URL is safe, and a high score does not prove it is malicious.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .config import LEVEL_ADVICE, MAX_RULE_ADVICE, RISK_BANDS
from .rules import RULES, RULES_BY_ID, Indicator
from .validator import InvalidURLError, defang, parse_url

logger = logging.getLogger(__name__)

__all__ = ["AnalysisResult", "InvalidURLError", "analyze_url", "risk_level_for"]


@dataclass
class AnalysisResult:
    """Everything we learned about one URL."""

    timestamp: str
    input_url: str
    defanged_url: str
    hostname: str
    registered_domain: str
    score: int
    risk_level: str
    indicators: list = field(default_factory=list)       # list of Indicator
    notes: list = field(default_factory=list)            # extra information (not scored)
    recommendations: list = field(default_factory=list)

    def to_row(self) -> dict:
        """Flatten into a plain dict (used for the history table and the CSV)."""
        return {
            "timestamp": self.timestamp,
            "url": self.input_url,
            "defanged_url": self.defanged_url,
            "hostname": self.hostname,
            "registered_domain": self.registered_domain,
            "risk_score": self.score,
            "risk_level": self.risk_level,
            "indicator_count": len(self.indicators),
            "indicators": "; ".join(f"{i.title} (+{i.points})" for i in self.indicators),
            "explanations": " | ".join(i.explanation for i in self.indicators),
            "recommendations": " | ".join(self.recommendations),
            "indicator_titles": [i.title for i in self.indicators],   # for charts; not exported to CSV
        }


def risk_level_for(score: int) -> str:
    """Convert a 0-100 score into Low / Medium / High / Critical."""
    for minimum, label in RISK_BANDS:
        if score >= minimum:
            return label
    return RISK_BANDS[-1][1]


def analyze_url(raw_url: str, now: Optional[datetime] = None) -> AnalysisResult:
    """Analyze the TEXT of a URL. Raises InvalidURLError if the input is unusable.

    This function never opens the URL or contacts any server.
    """
    parsed = parse_url(raw_url)            # may raise InvalidURLError
    now = now or datetime.now()

    indicators = []
    notes = []
    for rule in RULES:
        try:
            finding = rule.check(parsed)
        except Exception:                  # one buggy rule must not crash the whole app
            logger.exception("Rule %s failed", rule.rule_id)
            notes.append(f"The rule '{rule.title}' could not be evaluated for this URL.")
            continue
        if finding is not None:
            indicators.append(finding)

    indicators.sort(key=lambda i: i.points, reverse=True)
    total = sum(i.points for i in indicators)
    score = min(100, total)
    level = risk_level_for(score)

    # Extra information that is shown but NOT scored
    if parsed.scheme_assumed:
        notes.append("No http:// or https:// was typed, so the HTTPS check was skipped.")
    elif parsed.scheme == "https":
        notes.append("The URL uses HTTPS. That only means the connection is encrypted - phishing sites use HTTPS too.")
    if total > 100:
        notes.append(f"The rules added up to {total} points; the score is capped at 100.")
    if not indicators:
        notes.append("No rule matched. That does not prove the URL is safe - these rules cannot see everything.")

    # Recommendations: general advice for the level + tips from the rules that fired
    recommendations = list(LEVEL_ADVICE[level])
    for indicator in indicators[:MAX_RULE_ADVICE]:
        advice = RULES_BY_ID[indicator.rule_id].advice
        if advice not in recommendations:
            recommendations.append(advice)

    return AnalysisResult(
        timestamp=now.strftime("%Y-%m-%d %H:%M:%S"),
        input_url=parsed.original,
        defanged_url=defang(parsed.original),
        hostname=parsed.hostname,
        registered_domain=parsed.registered_domain,
        score=score,
        risk_level=level,
        indicators=indicators,
        notes=notes,
        recommendations=recommendations,
    )

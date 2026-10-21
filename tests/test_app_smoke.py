"""Smoke tests for the Streamlit dashboard, run without opening a browser.

They use Streamlit's AppTest helper: it runs app.py like a real session, types
into the boxes and clicks the buttons.
"""

from pathlib import Path

import pytest

pytest.importorskip("streamlit.testing.v1")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP_FILE = str(Path(__file__).resolve().parent.parent / "app.py")


def new_app():
    return AppTest.from_file(APP_FILE, default_timeout=60).run()


def click(app, label):
    next(button for button in app.button if button.label == label).click()
    return app.run()


def test_app_starts_without_errors():
    app = new_app()
    assert not app.exception


def test_analyzing_a_url_shows_score_and_stores_history():
    app = new_app()
    app.text_input(key="url_input").set_value("http://45.12.30.77/verify-account/login")
    app = click(app, "Analyze URL")
    assert not app.exception
    assert app.metric[0].value == "60 / 100"
    assert len(app.session_state["history"]) == 1
    assert app.session_state["history"][0]["risk_level"] == "High"


def test_invalid_input_shows_a_friendly_error_and_no_history():
    app = new_app()
    app.text_input(key="url_input").set_value("javascript:alert(1)")
    app = click(app, "Analyze URL")
    assert not app.exception
    assert len(app.error) >= 1
    assert app.session_state["history"] == []


def test_sample_button_analyzes_and_clear_history_empties_it():
    app = new_app()
    app = click(app, "Ordinary website")
    assert not app.exception
    assert len(app.session_state["history"]) == 1
    # Button label changed to include an emoji prefix in the redesign
    app = click(app, "🗑️ Clear history")
    assert app.session_state["history"] == []


def test_batch_mode_reports_good_and_bad_lines():
    app = new_app()
    app.text_area(key="batch_input").set_value("https://example.com\nftp://bad.example\nhttp://bit.ly/x")
    app = click(app, "Analyze all")
    assert not app.exception
    assert len(app.session_state["history"]) == 2       # the bad line is skipped
    assert len(app.error) == 1

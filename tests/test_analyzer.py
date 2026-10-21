"""Tests for the rules and the scoring (rules.py + analyzer.py)."""

import pytest

from cybersentry.analyzer import analyze_url, risk_level_for
from cybersentry.config import SAMPLE_URLS
from cybersentry.rules import RULES_BY_ID
from cybersentry.validator import InvalidURLError


def fired(url_text):
    """Return {rule_id: points} for the rules that fired on a URL."""
    return {i.rule_id: i.points for i in analyze_url(url_text).indicators}


# ---------------------------------------------------------------- scoring basics
def test_clean_url_scores_zero_and_low():
    result = analyze_url("https://www.example.com/about")
    assert result.score == 0
    assert result.risk_level == "Low"
    assert result.indicators == []
    assert any("does not prove" in note for note in result.notes)


@pytest.mark.parametrize(
    "score, level",
    [(0, "Low"), (19, "Low"), (20, "Medium"), (44, "Medium"),
     (45, "High"), (69, "High"), (70, "Critical"), (100, "Critical")],
)
def test_risk_level_boundaries(score, level):
    assert risk_level_for(score) == level


def test_score_is_the_sum_of_points_and_is_capped_at_100():
    url = ("http://paypal.com@secure-login-verify-account.paypal.com.a.b.c.d.e.example-site.xyz:8080"
           "/http://x.example/setup.exe?redirect=http://evil.example")
    result = analyze_url(url)
    total = sum(i.points for i in result.indicators)
    assert total > 100
    assert result.score == 100
    assert result.risk_level == "Critical"
    assert any("capped" in note for note in result.notes)


def test_invalid_input_raises():
    with pytest.raises(InvalidURLError):
        analyze_url("javascript:alert(1)")


# ---------------------------------------------------------------- one test per rule
def test_public_ip_host():
    assert fired("http://45.12.30.77/")["ip_host"] == 35


def test_private_ip_host_scores_less():
    assert fired("http://192.168.1.10/")["ip_host"] == 20


def test_disguised_numeric_host():
    assert fired("http://2130706433/")["ip_host"] == 35


def test_at_symbol_with_domain_like_username():
    assert fired("http://paypal.com@free-gift.example.xyz/claim")["at_symbol"] == 35


def test_at_symbol_with_plain_username():
    assert fired("http://bob@example.com/")["at_symbol"] == 25


@pytest.mark.parametrize("length, expected", [(60, None), (80, 5), (120, 10), (230, 15)])
def test_url_length_tiers(length, expected):
    url = "https://example.com/" + "a" * (length - len("https://example.com/"))
    assert fired(url).get("url_length") == expected


@pytest.mark.parametrize(
    "host, expected",
    [("www.example.com", None), ("a.b.example.com", None), ("a.b.c.example.com", 10), ("a.b.c.d.e.example.com", 20)],
)
def test_subdomain_tiers(host, expected):
    assert fired(f"https://{host}/").get("many_subdomains") == expected


def test_keywords_are_capped():
    assert fired("https://example.com/login")["suspicious_keywords"] == 5
    assert fired("https://example.com/login/verify/account/secure/update")["suspicious_keywords"] == 15


def test_brand_inside_someone_elses_domain():
    assert fired("https://paypal-secure.example.com/")["brand_impersonation"] == 30


def test_brand_real_domain_used_as_decoy_scores_extra():
    assert fired("https://paypal.com.example.net/")["brand_impersonation"] == 40


def test_decoy_bonus_needs_the_real_domain_as_a_whole_chunk():
    assert fired("https://pineapple.com/")["brand_impersonation"] == 30     # "apple.com" is only inside a word
    assert fired("https://login.apple.com.example.net/")["brand_impersonation"] == 40


def test_official_brand_domains_do_not_trigger_brand_rules():
    assert "brand_impersonation" not in fired("https://www.paypal.com/signin")
    assert "brand_impersonation" not in fired("https://login.microsoftonline.com/")
    assert "brand_impersonation" not in fired("https://www.google.co.in/")


@pytest.mark.parametrize("host", ["paypa1.com", "g00gle.com", "rnicrosoft.com", "arnazon.com"])
def test_lookalike_spellings(host):
    assert "lookalike_characters" in fired(f"https://{host}/")


def test_real_brands_are_not_lookalikes():
    assert "lookalike_characters" not in fired("https://www.paypal.com/")


def test_punycode_host_and_its_decoded_form():
    result = analyze_url("https://xn--pple-43d.com/")
    indicator = next(i for i in result.indicators if i.rule_id == "punycode_unicode")
    assert indicator.points == 25
    assert "decodes to" in indicator.explanation
    assert "many_hyphens" not in {i.rule_id for i in result.indicators}   # "xn--" is not real hyphens


def test_unicode_host():
    assert "punycode_unicode" in fired("https://аpple.com/")   # Cyrillic a


def test_plain_http_is_flagged_but_a_missing_scheme_is_not():
    assert fired("http://example.com/")["no_https"] == 10
    result = analyze_url("example.com")
    assert "no_https" not in {i.rule_id for i in result.indicators}
    assert any("HTTPS check was skipped" in note for note in result.notes)


@pytest.mark.parametrize("host, expected", [("a-b.example.com", None), ("a-b-c.example.com", 5), ("a-b-c-d.example.com", 10)])
def test_hyphen_tiers(host, expected):
    assert fired(f"https://{host}/").get("many_hyphens") == expected


def test_suspicious_tld():
    assert fired("https://something.xyz/")["suspicious_tld"] == 10
    assert "suspicious_tld" not in fired("https://something.com/")


def test_url_shortener():
    assert fired("https://bit.ly/abc")["url_shortener"] == 15


def test_unusual_port_but_not_default_ports():
    assert fired("https://example.com:8443/")["unusual_port"] == 10
    assert "unusual_port" not in fired("https://example.com:443/")


def test_embedded_url_plain_and_encoded():
    assert "embedded_url" in fired("https://example.com/r?url=http://other.example")
    assert "embedded_url" in fired("https://example.com/r?url=http%3A%2F%2Fother.example")


def test_brand_in_path_only():
    assert "brand_in_path" in fired("https://example.com/paypal/login")


def test_brand_in_path_is_ignored_on_known_official_domains():
    assert "brand_in_path" not in fired("https://www.google.com/search?q=paypal")


def test_risky_file_extension():
    assert fired("https://example.com/files/setup.exe")["risky_extension"] == 10
    assert "risky_extension" not in fired("https://example.com/files/readme.txt")


# ---------------------------------------------------------------- integrity checks
ALL_TEST_URLS = [url for _, url in SAMPLE_URLS] + [
    "http://192.168.1.10/login", "https://paypa1.com", "https://xn--pple-43d.com",
    "http://2130706433/", "https://bit.ly/x", "http://bob@example.com:8080/a.exe",
    "https://a.b.c.d.e.example.com/", "example.com", "@evil.com",
]


@pytest.mark.parametrize("url", ALL_TEST_URLS)
def test_every_indicator_is_explained_and_within_its_rule_maximum(url):
    result = analyze_url(url)
    assert 0 <= result.score <= 100
    assert not any("could not be evaluated" in note for note in result.notes)   # no rule crashed
    for indicator in result.indicators:
        assert indicator.explanation.strip()
        assert 0 < indicator.points <= RULES_BY_ID[indicator.rule_id].max_points
    assert result.recommendations                                              # always some advice
    assert "http://" not in result.defanged_url.lower()                        # defanged copy is not clickable


def test_sample_urls_cover_every_risk_level():
    levels = {analyze_url(url).risk_level for _, url in SAMPLE_URLS}
    assert levels == {"Low", "Medium", "High", "Critical"}


def test_a_crashing_rule_does_not_crash_the_analysis(monkeypatch):
    from cybersentry import analyzer

    class BrokenRule:
        rule_id, title, advice = "broken", "Broken rule", ""

        @staticmethod
        def check(_url):
            raise RuntimeError("boom")

    monkeypatch.setattr(analyzer, "RULES", [BrokenRule])
    result = analyze_url("https://example.com")
    assert result.score == 0
    assert any("could not be evaluated" in note for note in result.notes)


# ---------------------------------------------------------------- documented limitations
# These tests do not describe "wanted" behaviour. They document what simple
# heuristics get wrong, so you can talk about it honestly in your presentation.
def test_known_false_positive_innocent_name_contains_a_brand():
    """A fruit shop called pineapple matches the brand 'apple'."""
    assert "brand_impersonation" in fired("https://www.pineapple.com/")


def test_known_false_negative_clean_looking_domain_scores_zero():
    """A brand-new phishing domain with no suspicious text looks perfectly normal."""
    assert analyze_url("https://acme-portal.net/start").score == 0


def test_known_false_negative_url_shorteners_hide_the_target():
    """We cannot see where a short link leads, because we never open links."""
    assert analyze_url("https://bit.ly/3AbCdEf").score < 45

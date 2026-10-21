"""Tests for validator.py - is bad input rejected, and is good input parsed correctly?"""

import pytest

from cybersentry.config import MAX_URL_LENGTH
from cybersentry.validator import InvalidURLError, defang, parse_url, refang


def test_parses_a_normal_https_url():
    url = parse_url("https://www.example.com/about?x=1")
    assert url.scheme == "https"
    assert url.scheme_assumed is False
    assert url.hostname == "www.example.com"
    assert url.registered_domain == "example.com"
    assert url.subdomain_count == 1
    assert url.path == "/about"


def test_missing_scheme_is_assumed_and_flagged():
    url = parse_url("example.com/page")
    assert url.scheme_assumed is True
    assert url.hostname == "example.com"


def test_host_with_port_but_no_scheme_is_not_mistaken_for_a_scheme():
    url = parse_url("example.com:8080/x")
    assert url.port == 8080
    assert url.hostname == "example.com"


def test_two_part_suffix_like_co_uk():
    url = parse_url("https://a.b.example.co.uk/")
    assert url.registered_domain == "example.co.uk"
    assert url.subdomain_count == 2


def test_hostname_is_lowercased_and_trailing_dot_removed():
    assert parse_url("https://EXAMPLE.com./").hostname == "example.com"


def test_ipv4_and_ipv6_hosts():
    assert parse_url("http://192.168.1.10/").ip is not None
    assert parse_url("http://[::1]:8000/").ip is not None


def test_obfuscated_numeric_host():
    assert parse_url("http://2130706433/").is_obfuscated_ip is True
    assert parse_url("http://0x7f.0.0.1/").is_obfuscated_ip is True
    assert parse_url("http://123.example.com/").is_obfuscated_ip is False


def test_userinfo_is_detected():
    url = parse_url("http://paypal.com@evil.example/")
    assert url.userinfo == "paypal.com"
    assert url.hostname == "evil.example"


@pytest.mark.parametrize(
    "bad_input",
    [
        "",
        "   ",
        "http://",
        "http:///path",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "mailto:someone@example.com",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "http://exa mple.com",            # space inside
        "http://example.com/\nnext",      # newline inside
        "http://exam​ple.com",       # invisible zero-width character
        "http://example.com:99999",       # port out of range
        "http://example.com:abc",         # port not a number
        "http://[::1",                    # broken IPv6
        "http://a..b",                    # empty label
        "http://exa<mple>.com",           # characters not allowed in host names
    ],
)
def test_bad_input_is_rejected_with_invalid_url_error(bad_input):
    with pytest.raises(InvalidURLError):
        parse_url(bad_input)


def test_too_long_input_is_rejected():
    with pytest.raises(InvalidURLError):
        parse_url("https://example.com/" + "a" * MAX_URL_LENGTH)


def test_non_text_input_is_rejected():
    with pytest.raises(InvalidURLError):
        parse_url(None)          # type: ignore[arg-type]


def test_error_messages_do_not_echo_the_input():
    secret = "<script>alert('x')</script>"
    with pytest.raises(InvalidURLError) as info:
        parse_url(f"http://{secret}.com")
    assert "script" not in str(info.value)


def test_refang_and_defang_round_trip():
    assert refang("hxxps://example[.]com/a") == "https://example.com/a"
    assert refang("  HXXP://example[.]com ") == "http://example.com"
    assert defang("https://example.com/a") == "hxxps://example[.]com/a"
    assert "http" not in defang("http://example.com")


def test_defang_also_neutralizes_urls_hidden_in_the_query_and_leaves_plain_words():
    assert "http" not in defang("https://a.example/r?u=http://b.example")
    assert defang("httpbin.org/get") == "httpbin[.]org/get"


def test_defanged_input_can_be_analyzed():
    url = parse_url("hxxps://example[.]com/login")
    assert url.scheme == "https"
    assert url.hostname == "example.com"


# ---------------------------------------------------------------------------
# Dotless-hostname rejection (must have at least one dot and a real TLD)
# ---------------------------------------------------------------------------

def test_dotless_word_abc_is_rejected():
    with pytest.raises(InvalidURLError, match="doesn't look like a valid URL"):
        parse_url("abc")


def test_dotless_word_localhost_is_rejected():
    with pytest.raises(InvalidURLError, match="doesn't look like a valid URL"):
        parse_url("localhost")


def test_dotless_word_with_scheme_is_rejected():
    with pytest.raises(InvalidURLError, match="doesn't look like a valid URL"):
        parse_url("http://abc")


def test_valid_ip_url_still_passes():
    url = parse_url("http://192.168.1.1/login")
    assert url.ip is not None
    assert str(url.ip) == "192.168.1.1"

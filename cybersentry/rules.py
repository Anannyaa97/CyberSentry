"""
rules.py - the detection rules.

Every rule is ONE small function that looks at a ParsedURL and returns either:
  * an Indicator (what was found, how many points, and a plain-English reason), or
  * None (nothing suspicious for this rule).

At the bottom, RULES lists all rules. To add a new rule:
  1. write a check_...() function,
  2. add its points to POINTS in config.py,
  3. add a Rule(...) entry to RULES,
  4. add a test in tests/test_analyzer.py.

No rule ever connects to the internet - they only read the text of the URL.
"""

import re
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import unquote

from .config import (
    BRANDS,
    HYPHEN_TIERS,
    KNOWN_OFFICIAL_DOMAINS,
    LENGTH_TIERS,
    POINTS,
    RISKY_EXTENSIONS,
    SUBDOMAIN_TIERS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from .validator import ParsedURL


@dataclass
class Indicator:
    """One finding: which rule fired, its points, and why."""

    rule_id: str
    title: str
    points: int
    explanation: str


@dataclass
class Rule:
    """A rule plus the information shown on the 'How it works' page."""

    rule_id: str
    title: str
    max_points: int
    description: str   # what the rule looks for
    advice: str        # tip shown to the user when the rule fires
    check: Callable[[ParsedURL], Optional[Indicator]]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _show(text: str, limit: int = 60) -> str:
    """Shorten long text so explanations stay readable."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _is_official(brand: str, registered_domain: str) -> bool:
    """True if the registered domain is one of the brand's official domains."""
    return registered_domain in BRANDS[brand]


def _lookalike_variants(hostname: str) -> set:
    """Undo common look-alike tricks: 0->o, 3->e, 4->a, 5->s, 7->t, 1->l or i, rn->m."""
    base = hostname.translate(str.maketrans("03457", "oeast"))
    variants = {base.replace("1", "l"), base.replace("1", "i")}
    variants |= {v.replace("rn", "m") for v in variants}
    return variants


def _decode_idna(hostname: str) -> Optional[str]:
    """Turn 'xn--...' (punycode) back into the letters a browser may show."""
    try:
        return hostname.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------
def check_ip_host(url: ParsedURL) -> Optional[Indicator]:
    host = _show(url.hostname)
    if url.is_obfuscated_ip:
        return Indicator(
            "ip_host", "Number-only host name (disguised IP address)", POINTS["ip_public"],
            f"The host '{host}' is written as plain numbers (decimal, hex or octal). Browsers can turn "
            "this into an IP address. Attackers use this format to hide where a link really goes.",
        )
    if url.ip is None:
        return None
    if url.ip.is_global:
        return Indicator(
            "ip_host", "IP address instead of a domain name", POINTS["ip_public"],
            f"The link goes straight to the IP address {host} instead of a normal domain name. "
            "Real services almost always use a domain name; attackers often use raw IP addresses "
            "because they are cheap, disposable and need no domain registration.",
        )
    return Indicator(
        "ip_host", "IP address in a private/local range", POINTS["ip_private"],
        f"The host {host} is a private, local or reserved address. It only works inside a network "
        "(for example a home or office). Links like this are unusual in emails and messages.",
    )


def check_at_symbol(url: ParsedURL) -> Optional[Indicator]:
    if url.userinfo is None:
        return None
    username = url.userinfo.split(":")[0]
    points = POINTS["at_symbol"]
    extra = ""
    if "." in username:
        points += POINTS["at_symbol_looks_like_domain"]
        extra = (" The text before the '@' even looks like a domain name - a classic trick to make "
                 "a link look like it belongs to a trusted site.")
    return Indicator(
        "at_symbol", "'@' symbol in the address", points,
        f"Everything before the '@' ('{_show(username, 40)}') is just a username. The browser really "
        f"connects to '{_show(url.hostname)}'. Attackers put a trusted-looking name in front of the '@' "
        f"to fool people who only read the beginning of the link.{extra}",
    )


def check_url_length(url: ParsedURL) -> Optional[Indicator]:
    length = len(url.original)
    for threshold, points in LENGTH_TIERS:
        if length >= threshold:
            return Indicator(
                "url_length", "Unusually long URL", points,
                f"The URL is {length} characters long (the warning starts at {threshold}). Very long "
                "URLs can bury the real domain among confusing text. Note that some honest sites also "
                "produce long links (search results, tracking links).",
            )
    return None


def check_many_subdomains(url: ParsedURL) -> Optional[Indicator]:
    if url.is_ip_host:
        return None
    for threshold, points in SUBDOMAIN_TIERS:
        if url.subdomain_count >= threshold:
            return Indicator(
                "many_subdomains", "Excessive subdomains", points,
                f"The host name has {url.subdomain_count} subdomain levels in front of the main domain. "
                "Attackers stack many words at the start so a trusted-looking name appears first. "
                f"Read the host from right to left: the real site is '{_show(url.registered_domain)}'.",
            )
    return None


def check_suspicious_keywords(url: ParsedURL) -> Optional[Indicator]:
    text = " ".join([url.hostname, unquote(url.path), unquote(url.query)]).lower()
    found = [word for word in SUSPICIOUS_KEYWORDS if word in text]
    if not found:
        return None
    points = min(len(found) * POINTS["keyword_each"], POINTS["keyword_max"])
    return Indicator(
        "suspicious_keywords", "Phishing-style keywords", points,
        f"Words often used in phishing pages were found: {', '.join(found[:8])}. Phishing pages "
        "pretend to be about logins, accounts or security. Many honest sites use these words too, "
        "so this rule only adds a few points.",
    )


def check_brand_impersonation(url: ParsedURL) -> Optional[Indicator]:
    if url.is_ip_host:
        return None
    for brand in BRANDS:
        if brand in url.hostname and not _is_official(brand, url.registered_domain):
            points = POINTS["brand_in_host"]
            extra = ""
            # a decoy is the brand's REAL domain as a whole chunk: "paypal.com.evil.net" (yes), "pineapple.com" (no)
            decoys = [d for d in BRANDS[brand] if re.search(rf"(^|\.){re.escape(d)}(\.|$)", url.hostname)]
            if decoys:
                points += POINTS["brand_real_domain_embedded"]
                extra = (f" It even contains the real address '{decoys[0]}' as a decoy, but that is only "
                         "a subdomain or a piece of someone else's domain.")
            return Indicator(
                "brand_impersonation", "Brand name inside someone else's domain", points,
                f"The host name '{_show(url.hostname)}' contains the brand name '{brand}', but the site's "
                f"real domain is '{_show(url.registered_domain)}', which is not an official {brand} domain "
                f"(according to this tool's small demo list).{extra}",
            )
    return None


def check_lookalike_characters(url: ParsedURL) -> Optional[Indicator]:
    if url.is_ip_host:
        return None
    variants = _lookalike_variants(url.hostname)
    for brand in BRANDS:
        if brand in url.hostname or _is_official(brand, url.registered_domain):
            continue   # exact brand names are handled by the brand rule
        if any(brand in variant for variant in variants):
            return Indicator(
                "lookalike_characters", "Look-alike spelling of a brand", POINTS["lookalike"],
                f"The host name '{_show(url.hostname)}' looks like '{brand}' once look-alike characters "
                "are swapped back (for example 0 for o, 1 for l, or 'rn' for 'm'). Attackers register "
                "names that look right at a quick glance.",
            )
    return None


def check_punycode_unicode(url: ParsedURL) -> Optional[Indicator]:
    if url.is_ip_host:
        return None
    has_puny = any(label.startswith("xn--") for label in url.labels)
    non_ascii = not url.hostname.isascii()
    if not (has_puny or non_ascii):
        return None
    detail = ""
    if has_puny:
        decoded = _decode_idna(url.hostname)
        if decoded:
            detail = f" The encoded name decodes to '{_show(decoded)}'."
    return Indicator(
        "punycode_unicode", "Internationalized / look-alike letters in the host", POINTS["punycode_unicode"],
        "The host name uses letters from other alphabets (or the 'xn--' encoding for them). Some of these "
        "letters look identical to English letters (for example Cyrillic 'а' and Latin 'a'), which lets "
        f"attackers fake a famous name.{detail} Honest sites in other languages use such names too.",
    )


def check_no_https(url: ParsedURL) -> Optional[Indicator]:
    if url.scheme == "http" and not url.scheme_assumed:
        return Indicator(
            "no_https", "Not using HTTPS", POINTS["no_https"],
            "The link uses plain http://, so the connection is not encrypted. Sites that ask for logins "
            "or payments should use https://. (The reverse is NOT true: phishing sites can use https:// too.)",
        )
    return None


def check_many_hyphens(url: ParsedURL) -> Optional[Indicator]:
    if url.is_ip_host:
        return None
    count = url.hostname.replace("xn--", "").count("-")   # the "xn--" punycode prefix is not a real hyphen
    for threshold, points in HYPHEN_TIERS:
        if count >= threshold:
            return Indicator(
                "many_hyphens", "Many hyphens in the host name", points,
                f"The host name contains {count} hyphens. Phishing domains often chain words together "
                "(like secure-login-bank-example.com) to imitate a trusted name.",
            )
    return None


def check_suspicious_tld(url: ParsedURL) -> Optional[Indicator]:
    if url.tld in SUSPICIOUS_TLDS:
        return Indicator(
            "suspicious_tld", "Domain ending often seen in phishing", POINTS["suspicious_tld"],
            f"The domain ends in '.{url.tld}', an ending that appears often in phishing and spam reports "
            "(partly because it is cheap or free to register). Many honest sites use it too, so this is only a mild signal.",
        )
    return None


def check_url_shortener(url: ParsedURL) -> Optional[Indicator]:
    if url.registered_domain in URL_SHORTENERS or url.hostname in URL_SHORTENERS:
        return Indicator(
            "url_shortener", "Link-shortening service", POINTS["shortener"],
            f"'{_show(url.registered_domain)}' is a link shortener. It hides the final destination, and "
            "CyberSentry cannot see where it leads because it never opens links.",
        )
    return None


def check_unusual_port(url: ParsedURL) -> Optional[Indicator]:
    if url.port not in (None, 80, 443):
        return Indicator(
            "unusual_port", "Unusual port number", POINTS["unusual_port"],
            f"The URL asks for port {url.port}. Ordinary websites use the default ports (80 for http, 443 "
            "for https), which browsers hide. A visible custom port is unusual for a public website.",
        )
    return None


def check_embedded_url(url: ParsedURL) -> Optional[Indicator]:
    tail = unquote(unquote(f"{url.path}?{url.query}#{url.fragment}")).lower()   # decode twice: %253A tricks
    if re.search(r"https?://", tail):
        return Indicator(
            "embedded_url", "Another web address hidden inside the URL", POINTS["embedded_url"],
            "A second web address is hidden in the path or query (for example after 'redirect='). "
            "Attackers use this to send you through a trusted-looking page to a harmful one. "
            "Some honest sites (archives, login redirects) do this too.",
        )
    return None


def check_brand_in_path(url: ParsedURL) -> Optional[Indicator]:
    if url.registered_domain in KNOWN_OFFICIAL_DOMAINS:
        return None   # e.g. google.com/search?q=paypal is not impersonation
    text = unquote(f"{url.path} {url.query}").lower()
    for brand in BRANDS:
        if brand in text and brand not in url.hostname:
            return Indicator(
                "brand_in_path", "Brand name only in the path", POINTS["brand_in_path"],
                f"The brand name '{brand}' appears after the domain, but the domain "
                f"('{_show(url.registered_domain)}') is not an official {brand} domain. Anyone can put "
                "a brand name in the path of their own site to make a link look official.",
            )
    return None


def check_risky_extension(url: ParsedURL) -> Optional[Indicator]:
    path = unquote(url.path).lower()
    for ext in RISKY_EXTENSIONS:
        if path.endswith(ext):
            return Indicator(
                "risky_extension", "Link to a risky file type", POINTS["risky_extension"],
                f"The link points to a file ending in '{ext}'. Programs, scripts, disk images, archives and "
                "macro-enabled documents are common ways to deliver malware. Many honest downloads use these types too.",
            )
    return None


# ---------------------------------------------------------------------------
# The rule registry (also used to build the "How it works" table)
# ---------------------------------------------------------------------------
RULES = [
    Rule("ip_host", "IP address instead of a domain name", POINTS["ip_public"],
         "The host is an IP address (or a number disguised as one) instead of a name.",
         "Prefer links that use a proper domain name. If someone told you to visit an IP address, confirm with them through another channel.",
         check_ip_host),
    Rule("at_symbol", "'@' symbol in the address", POINTS["at_symbol"] + POINTS["at_symbol_looks_like_domain"],
         "Text before an '@' in the address, which the browser treats as a username rather than the site.",
         "Read the part AFTER the '@' - that is where the link really goes.",
         check_at_symbol),
    Rule("url_length", "Unusually long URL", LENGTH_TIERS[0][1],
         "URLs of 75, 100 or 200+ characters (more points for longer).",
         "Look at the real domain (the part before the first single '/') instead of the whole long address.",
         check_url_length),
    Rule("many_subdomains", "Excessive subdomains", SUBDOMAIN_TIERS[0][1],
         "Three or more (or five or more) labels in front of the main domain.",
         "Read the host name from right to left: the real domain is the last two parts.",
         check_many_subdomains),
    Rule("suspicious_keywords", "Phishing-style keywords", POINTS["keyword_max"],
         "Words such as login, verify, secure, account or update in the host, path or query (5 points each, capped).",
         "Be careful with pages that ask you to log in, verify or confirm something. Open the official site by typing its address yourself.",
         check_suspicious_keywords),
    Rule("brand_impersonation", "Brand name inside someone else's domain",
         POINTS["brand_in_host"] + POINTS["brand_real_domain_embedded"],
         "A well-known brand name inside a host whose real domain is not the brand's.",
         "Go to the brand's official site by typing its address or using a bookmark rather than this link.",
         check_brand_impersonation),
    Rule("lookalike_characters", "Look-alike spelling of a brand", POINTS["lookalike"],
         "A brand spelled with swapped characters, like paypa1 or rnicrosoft.",
         "Compare the domain with the real brand, letter by letter.",
         check_lookalike_characters),
    Rule("punycode_unicode", "Internationalized / look-alike letters in the host", POINTS["punycode_unicode"],
         "'xn--' encoded labels or non-English letters in the host name (homograph attacks).",
         "Do not enter credentials on domains with unusual characters; type the address yourself.",
         check_punycode_unicode),
    Rule("no_https", "Not using HTTPS", POINTS["no_https"],
         "The address starts with http:// instead of https://.",
         "Avoid entering passwords or payment details on pages without https:// (but https:// alone does not prove a site is safe).",
         check_no_https),
    Rule("many_hyphens", "Many hyphens in the host name", HYPHEN_TIERS[0][1],
         "Two or three (or more) hyphens in the host name.",
         "Be wary of long hyphenated domain names that imitate a brand.",
         check_many_hyphens),
    Rule("suspicious_tld", "Domain ending often seen in phishing", POINTS["suspicious_tld"],
         "A domain ending (like .xyz or .top) that often appears in phishing reports.",
         "Treat links on unfamiliar domain endings with extra care and check where the message really came from.",
         check_suspicious_tld),
    Rule("url_shortener", "Link-shortening service", POINTS["shortener"],
         "A known link shortener such as bit.ly, which hides the real destination.",
         "Do not click shortened links from unknown senders; ask for the full link instead.",
         check_url_shortener),
    Rule("unusual_port", "Unusual port number", POINTS["unusual_port"],
         "A visible port other than 80 or 443.",
         "Avoid links with unusual port numbers unless you know the service.",
         check_unusual_port),
    Rule("embedded_url", "Another web address hidden inside the URL", POINTS["embedded_url"],
         "An http:// or https:// address inside the path or query (possible redirect).",
         "Be careful with links that contain another web address; they may send you somewhere else.",
         check_embedded_url),
    Rule("brand_in_path", "Brand name only in the path", POINTS["brand_in_path"],
         "A brand name after the domain, on a domain that is not the brand's.",
         "Check the domain name, not the page path - anyone can put a brand name in a path.",
         check_brand_in_path),
    Rule("risky_extension", "Link to a risky file type", POINTS["risky_extension"],
         "A link ending in .exe, .scr, .apk, .zip and similar file types.",
         "Do not download or run files from untrusted links; scan them with security software first.",
         check_risky_extension),
]

RULES_BY_ID = {rule.rule_id: rule for rule in RULES}

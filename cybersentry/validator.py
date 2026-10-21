"""
validator.py - turns the text a user typed into a clean, safe ParsedURL.

Job of this file: VALIDATE and PARSE. It never connects to the internet; it only
studies the characters of the URL. If the input is not usable, it raises
InvalidURLError with a friendly message (it never repeats the user's text back,
because user input is untrusted).
"""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from .config import MAX_URL_LENGTH, SECOND_LEVEL_LABELS


class InvalidURLError(ValueError):
    """Raised when the typed text cannot be treated as a URL we can analyze."""


@dataclass
class ParsedURL:
    """The pieces of a URL that the rules need."""

    original: str                 # what the user typed (cleaned up)
    normalized: str               # same, but with a scheme (http://) in front
    scheme: str                   # "http" or "https"
    scheme_assumed: bool          # True if the user did not type a scheme
    hostname: str                 # lower-case host name, e.g. "login.example.com"
    port: Optional[int]           # explicit port number, or None
    userinfo: Optional[str]       # text before an '@', or None
    path: str
    query: str
    fragment: str
    labels: list                  # host split on dots: ["login", "example", "com"]
    ip: Optional[object]          # an ipaddress object if the host is an IP, else None
    is_obfuscated_ip: bool        # host written as plain numbers like 2130706433
    registered_domain: str        # "main" domain, e.g. "example.com"
    tld: str                      # last label, e.g. "com"
    subdomain_count: int          # labels in front of the registered domain

    @property
    def is_ip_host(self) -> bool:
        return self.ip is not None or self.is_obfuscated_ip


# Something like "javascript:" or "mailto:" at the start (but not "example.com:8080")
_SCHEME_LIKE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):(?!\d)")
_HOST_CHARS = re.compile(r"[\w.\-]+")           # letters, digits, _ . - (any language)
_NUMERIC_LABEL = re.compile(r"\d+|0x[0-9a-f]+")  # 2130706433 or 0x7f


def refang(text: str) -> str:
    """Undo 'defanging' that analysts use to make links unclickable.

    hxxps://example[.]com  ->  https://example.com
    """
    text = text.strip()
    text = re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)
    return text.replace("[://]", "://").replace("[.]", ".")


def defang(text: str) -> str:
    """Make a URL safe to paste in reports/chats: it can no longer be clicked.

    https://example.com  ->  hxxps://example[.]com
    """
    # every "http://" or "https://" (also the ones hidden in a query) becomes "hxxp://"
    return re.sub(r"http(s?)(?=://)", r"hxxp\1", text, flags=re.IGNORECASE).replace(".", "[.]")


def _registered_domain(labels: list) -> str:
    """The 'main' domain: usually the last two labels (example.com),
    or three for names like example.co.uk."""
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_LABELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parse_url(raw: str) -> ParsedURL:
    """Validate and parse text into a ParsedURL, or raise InvalidURLError."""
    if not isinstance(raw, str):
        raise InvalidURLError("The URL must be text.")

    text = refang(raw)
    if not text:
        raise InvalidURLError("Please enter a URL.")
    if len(text) > MAX_URL_LENGTH:
        raise InvalidURLError(
            f"That text is longer than {MAX_URL_LENGTH} characters, which is more than this tool accepts."
        )
    # Reject spaces and invisible/control characters ("C" categories = control, format...)
    if any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in text):
        raise InvalidURLError("The URL contains spaces or hidden control characters. Remove them and try again.")

    # --- scheme handling -------------------------------------------------
    if "://" in text:
        scheme = text.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise InvalidURLError("Only http:// and https:// addresses are supported.")
        normalized, assumed = text, False
    else:
        match = _SCHEME_LIKE.match(text)
        if match:
            raise InvalidURLError(
                f"'{match.group(1)}:' links are not web addresses. "
                "Enter an address that starts with http:// or https://."
            )
        if text.startswith("//"):
            text = text[2:]
        scheme, normalized, assumed = "http", "http://" + text, True

    # --- split into parts (urlsplit never touches the network) -----------
    try:
        parts = urlsplit(normalized)
        port = parts.port           # raises ValueError for bad port numbers
        host = parts.hostname
    except ValueError:
        raise InvalidURLError(
            "This does not look like a valid URL. Check the host name and the port number."
        ) from None

    if not host:
        raise InvalidURLError("No host name found. A URL needs a site name, e.g. https://example.com/page")
    if host.endswith("."):
        host = host[:-1]

    netloc = parts.netloc
    userinfo = netloc.rpartition("@")[0] if "@" in netloc else None

    # --- host checks -----------------------------------------------------
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass

    if ip is not None:
        labels = [host]
        registered, tld, subdomains, obfuscated = host, "", 0, False
    else:
        if not _HOST_CHARS.fullmatch(host):
            raise InvalidURLError("The host name contains characters that are not allowed in domain names.")
        labels = host.split(".")
        if len(host) > 253 or any(label == "" or len(label) > 63 for label in labels):
            raise InvalidURLError("The host name is not valid (it has empty or overly long parts).")
        obfuscated = all(_NUMERIC_LABEL.fullmatch(label) for label in labels)
        if obfuscated:
            registered, tld, subdomains = host, "", 0
        else:
            if len(labels) == 1:
                raise InvalidURLError(
                    "This doesn't look like a valid URL or domain. Try something like example.com."
                )
            registered = _registered_domain(labels)
            tld = labels[-1] if len(labels) > 1 else ""
            subdomains = max(len(labels) - len(registered.split(".")), 0)

    return ParsedURL(
        original=text,
        normalized=normalized,
        scheme=scheme,
        scheme_assumed=assumed,
        hostname=host,
        port=port,
        userinfo=userinfo,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
        labels=labels,
        ip=ip,
        is_obfuscated_ip=obfuscated,
        registered_domain=registered,
        tld=tld,
        subdomain_count=subdomains,
    )

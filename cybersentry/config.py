"""
config.py - the "settings page" of CyberSentry.

Everything you might want to tweak lives here: point values, keyword lists,
brand names, risk bands, advice text and sample URLs. The rule LOGIC lives in
rules.py; the NUMBERS and WORD LISTS live here.

Beginner tip: change a number below, save, restart the app, and the scores
change. That is what "transparent scoring" means - there is no hidden magic.
"""

# ---------------------------------------------------------------------------
# Input limits (user input is untrusted, so we cap its size)
# ---------------------------------------------------------------------------
MAX_URL_LENGTH = 2048   # longer text is rejected as invalid input
MAX_BATCH_URLS = 25     # how many URLs the "several URLs" box accepts at once

# ---------------------------------------------------------------------------
# Risk bands: (lowest score in the band, label). Checked from top to bottom.
# NOTE: these are risk LEVELS of a heuristic score - they are NOT probabilities.
# ---------------------------------------------------------------------------
RISK_BANDS = [
    (70, "Critical"),
    (45, "High"),
    (20, "Medium"),
    (0, "Low"),
]
RISK_LEVEL_ORDER = ["Low", "Medium", "High", "Critical"]

# Short plain-English meaning of each level (shown in the dashboard)
LEVEL_SUMMARY = {
    "Low": "Few or no warning signs were found.",
    "Medium": "Some warning signs were found. Be careful.",
    "High": "Several warning signs were found. Treat this link as suspicious.",
    "Critical": "Many strong warning signs were found. Avoid this link.",
}

# General advice for each level (rule-specific advice is added on top)
LEVEL_ADVICE = {
    "Low": [
        "No strong warning signs were found, but a low score is NOT a guarantee that the link is safe.",
        "Still check who sent the link and whether you were expecting it.",
        "For banking or other sensitive sites, type the address yourself or use a bookmark.",
    ],
    "Medium": [
        "Do not enter passwords or payment details until you have verified the link.",
        "Check with the sender through a different channel (a phone call or the official app).",
        "Open the official website by typing its address yourself instead of using this link.",
    ],
    "High": [
        "Do not click this link or enter any information on the page it leads to.",
        "If it arrived in an email or message, treat that message as suspicious and do not reply.",
        "Report it to your IT/security team or to the service being imitated, if that applies.",
    ],
    "Critical": [
        "Avoid opening this link. Many strong warning signs were found.",
        "If you already entered a password, change it right away on the real site and turn on two-factor authentication.",
        "Report the message to your IT/security team and delete it.",
    ],
}

MAX_RULE_ADVICE = 5   # how many rule-specific tips to show at most

# ---------------------------------------------------------------------------
# Points. The final score is the SUM of the points of every rule that fired,
# capped at 100. Nothing is subtracted, nothing is hidden.
# ---------------------------------------------------------------------------
POINTS = {
    "ip_public": 35,                    # host is a public IP address (or a disguised one)
    "ip_private": 20,                   # host is a private / local IP address
    "at_symbol": 25,                    # text before an '@' in the address
    "at_symbol_looks_like_domain": 10,  # ...and that text looks like a domain (extra)
    "keyword_each": 5,                  # per phishing-style keyword found
    "keyword_max": 15,                  # cap for the keyword rule
    "brand_in_host": 30,                # brand name inside someone else's domain
    "brand_real_domain_embedded": 10,   # ...and the brand's real domain is used as a decoy (extra)
    "lookalike": 30,                    # brand spelled with look-alike characters (paypa1, rnicrosoft)
    "punycode_unicode": 25,             # xn-- labels or non-English letters in the host
    "no_https": 10,                     # plain http://
    "suspicious_tld": 10,               # domain ending often seen in phishing reports
    "shortener": 15,                    # link-shortening service
    "unusual_port": 10,                 # port other than 80 / 443
    "embedded_url": 10,                 # another web address hidden inside the URL
    "brand_in_path": 10,                # brand name only in the path/query part
    "risky_extension": 10,              # link to .exe, .scr, .apk ...
}

# Tiered rules: (threshold, points). The FIRST tier that matches is used.
LENGTH_TIERS = [(200, 15), (100, 10), (75, 5)]      # characters in the URL
SUBDOMAIN_TIERS = [(5, 20), (3, 10)]                # subdomain levels before the main domain
HYPHEN_TIERS = [(3, 10), (2, 5)]                    # hyphens in the host name

# ---------------------------------------------------------------------------
# Word lists used by the rules
# ---------------------------------------------------------------------------
# Words that phishing pages like to use. Many honest sites use them too, so
# they only add a few points (see POINTS above).
SUSPICIOUS_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "security", "account", "update", "confirm", "password",
    "bank", "wallet", "billing", "invoice", "payment", "suspend",
    "unlock", "recover", "authenticate", "validate", "webscr",
    "helpdesk", "alert",
]

# Domain endings that show up often in phishing/spam reports. Plenty of honest
# sites use them as well, so this is only a mild signal.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "mov",
    "icu", "cyou", "buzz", "loan", "work", "rest",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly",
}

# File endings that are often used to deliver malware.
RISKY_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".jar", ".vbs", ".ps1",
    ".iso", ".dmg", ".docm", ".xlsm", ".zip", ".rar",
)

# Used to work out the "main domain" without needing an external library:
# in names like  example.co.uk  the main domain is the last THREE parts.
SECOND_LEVEL_LABELS = {"co", "com", "org", "net", "gov", "edu", "ac"}

# A small DEMO list of well-known brands and their official domains.
# Add your own! Brand names should be at least 5 letters, otherwise short
# names would match inside unrelated words.
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "google.co.uk", "googleapis.com", "gstatic.com", "googleusercontent.com"},
    "gmail": {"gmail.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "windows.com", "azure.com"},
    "outlook": {"outlook.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com", "licdn.com"},
    "dropbox": {"dropbox.com"},
    "github": {"github.com", "github.io", "githubusercontent.com"},
    "adobe": {"adobe.com"},
    "fedex": {"fedex.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "onlinesbi": {"onlinesbi.sbi", "onlinesbi.com"},
    "irctc": {"irctc.co.in"},
}

# Every official domain of every brand above, in one set.
KNOWN_OFFICIAL_DOMAINS = set().union(*BRANDS.values())

# ---------------------------------------------------------------------------
# Example URLs for the sidebar buttons. They are made-up addresses; the app
# never opens them, and you should not open them either.
# ---------------------------------------------------------------------------
SAMPLE_URLS = [
    ("Ordinary website", "https://www.example.com/about"),
    ("Shortened link", "http://bit.ly/3AbCdEf"),
    ("Look-alike brand", "https://www.paypa1-secure.example.com/login"),
    ("IP address login page", "http://45.12.30.77/verify-account/login"),
    ("The '@' trick", "http://paypal.com@free-gift.example.xyz/claim"),
    ("Fake brand page", "http://secure-paypal-login.verify-account.example-site.top/signin?redirect=http://evil.example/steal"),
]

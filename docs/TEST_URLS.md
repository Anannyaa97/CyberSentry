# Test URLs and expected results

These are **made-up addresses**. CyberSentry only reads their text and never opens them - please don't open them either.
Copy any URL into the app (or use the sidebar example buttons) and compare it with the table.

Scores below are from the v1.0 rules and points in `cybersentry/config.py`. If you change a point value, re-check this table
(the automated tests will tell you what changed).

## Valid inputs

| # | Description | URL | Score | Level | Rules that fired |
|---|---|---|---|---|---|
| 1 | Ordinary site | `https://www.example.com/about` | 0 | Low | none |
| 2 | Real brand site | `https://www.paypal.com/signin` | 5 | Low | suspicious_keywords (+5) |
| 3 | Search mentioning a brand | `https://www.google.com/search?q=paypal` | 0 | Low | none |
| 4 | No scheme typed | `example.com/page` | 0 | Low | none (HTTPS check skipped) |
| 5 | Plain http | `http://example.com/` | 10 | Low | no_https (+10) |
| 6 | Shortened link | `http://bit.ly/3AbCdEf` | 25 | Medium | url_shortener (+15), no_https (+10) |
| 7 | Non-default port | `https://example.com:8443/` | 10 | Low | unusual_port (+10) |
| 8 | Risky file | `https://example.com/files/setup.exe` | 10 | Low | risky_extension (+10) |
| 9 | Look-alike (1 for l) | `https://paypa1.com/` | 30 | Medium | lookalike_characters (+30) |
| 10 | Look-alike (0 for o) | `https://g00gle.com/` | 30 | Medium | lookalike_characters (+30) |
| 11 | Look-alike (rn for m) | `https://rnicrosoft.com/` | 30 | Medium | lookalike_characters (+30) |
| 12 | Punycode host | `https://xn--pple-43d.com/` | 25 | Medium | punycode_unicode (+25) |
| 13 | Disguised IP (decimal) | `http://2130706433/` | 45 | High | ip_host (+35), no_https (+10) |
| 14 | Private IP | `http://192.168.1.10/login` | 35 | Medium | ip_host (+20), no_https (+10), suspicious_keywords (+5) |
| 15 | Public IP login | `http://45.12.30.77/verify-account/login` | 60 | High | ip_host (+35), suspicious_keywords (+15), no_https (+10) |
| 16 | Brand in someone else's domain | `https://paypal-secure.example.com/` | 35 | Medium | brand_impersonation (+30), suspicious_keywords (+5) |
| 17 | Brand + decoy real domain | `https://login.paypal.com.account-verify.example.net/` | 65 | High | brand_impersonation (+40), suspicious_keywords (+15), many_subdomains (+10) |
| 18 | The `@` trick | `http://paypal.com@free-gift.example.xyz/claim` | 55 | High | at_symbol (+35), no_https (+10), suspicious_tld (+10) |
| 19 | Look-alike + keywords | `https://www.paypa1-secure.example.com/login` | 40 | Medium | lookalike_characters (+30), suspicious_keywords (+10) |
| 20 | Everything at once | `http://secure-paypal-login.verify-account.example-site.top/signin?redirect=http://evil.example/steal` | 95 | Critical | brand_impersonation (+30), suspicious_keywords (+15), url_length (+10), no_https (+10), many_hyphens (+10), suspicious_tld (+10), embedded_url (+10) |

## Honest limitations (great for your presentation)

| # | Description | URL | Score | Level | What it teaches |
|---|---|---|---|---|---|
| 21 | **False positive** | `https://www.pineapple.com/` | 30 | Medium | A harmless name that contains the brand "apple" is flagged. |
| 22 | **False negative** | `https://acme-portal.net/start` | 0 | Low | A new phishing site with a clean-looking name scores 0. Low does not mean safe. |

## Inputs that must be rejected (friendly error, nothing added to history)

| Input | Why |
|---|---|
| *(empty)* | Nothing to analyze |
| `javascript:alert(1)` | Not a web address |
| `ftp://example.com/file` | Only http/https are supported |
| `http://exa mple.com` | Space inside the URL |
| `http://example.com:99999` | Port out of range |
| `http://` | No host name |
| `http://a..b` | Empty part in the host name |
| `mailto:someone@example.com` | Not a web address |

## Interesting extras

- `hxxps://example[.]com/login` - defanged links are accepted (they are turned back into normal text for analysis).
- `@evil.com` - valid input that starts with `@`; look at the CSV: the cell is neutralized so Excel won't treat it as a formula.
- `![x](http://evil.example/a.png)` - not a valid URL, and even if shown it would be escaped (no image is loaded).
